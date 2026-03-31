# PayPal OIDC Integration — Problems & Solutions

This document explains the problems encountered when integrating PayPal's OIDC with [BoxyHQ Jackson](https://github.com/boxyhq/jackson) and [Ory Kratos](https://www.ory.sh/kratos/), and how each was resolved.

---

## Architecture

```
Browser → Kratos → Jackson Bridge → PayPal
                    (this server)
```

- **Kratos** is Xflowpay's identity system. It speaks standard OIDC.
- **Jackson** is a protocol bridge (BoxyHQ). It connects to upstream identity providers and exposes a clean OIDC interface downstream.
- **PayPal** is the upstream identity provider. It offers OIDC, but with non-standard behavior.

The Jackson bridge sits between Kratos and PayPal. Kratos sees a spec-compliant OIDC provider (Jackson). Jackson deals with PayPal's quirks.

---

## Problems & Solutions

### Problem 1: Client Authentication Method Mismatch

**What happened**

Kratos initiated login → Jackson redirected to PayPal → user logged in → PayPal sent auth code back → Jackson's internal `openid-client` tried to exchange the code for tokens at PayPal's `/v1/oauth2/token` endpoint.

PayPal rejected it with:

```
invalid_client: Client Authentication failed
```

**Root cause**

PayPal's OIDC discovery document declares:

```json
{
  "token_endpoint_auth_methods_supported": ["client_secret_basic"]
}
```

This means PayPal **only** accepts client credentials in the `Authorization: Basic` header. But Jackson's `openid-client` (v6) was sending them as `client_secret_post` — i.e., `client_id` and `client_secret` in the POST body.

PayPal saw no `Authorization` header and rejected the request.

**Solution (Shim 1)**

Intercept HTTPS requests to PayPal's token endpoint. When the request body contains `client_id` and `client_secret`:

1. Remove them from the body
2. Encode as `Base64(client_id:client_secret)`
3. Set `Authorization: Basic <encoded>` header

```
Before:  POST body = client_id=xxx&client_secret=yyy&code=zzz
After:   POST body = code=zzz
         Authorization: Basic eHh4Onl5eQ==
```

This is a transport-level fix. No protocol semantics are altered — the credentials are the same, just moved to where PayPal expects them.

---

### Problem 2: Missing `id_token` in Token Response

**What happened**

After fixing the auth method, PayPal accepted the token request and returned:

```json
{
  "access_token": "A21AAJ...",
  "token_type": "Bearer",
  "expires_in": 28800,
  "refresh_token": "..."
}
```

Jackson's `openid-client` expected an `id_token` in this response (since `openid` scope was requested). It threw:

```
invalid response encountered
```

**Root cause**

PayPal's `/v1/oauth2/token` endpoint is primarily an OAuth 2.0 endpoint. Even when `openid` scope is requested, it does **not** return an `id_token`. PayPal has a separate legacy OIDC token endpoint (`/v1/identity/openidconnect/tokenservice`) that does return `id_token`, but authorization codes from `/v1/oauth2/token` cannot be redeemed there — they're scoped to the endpoint that issued them.

**Solution (Shim 2)**

When PayPal's token response is `200 OK` with an `access_token` but no `id_token`:

1. Call PayPal's userinfo endpoint (`GET /v1/oauth2/token/userinfo?schema=openid`) using the `access_token`
2. Extract the user's `sub`, `email`, `name`, `given_name`, `family_name`
3. Construct a conformant `id_token` JWT:
   - **Issuer** (`iss`): PayPal's origin (from discovery URL)
   - **Subject** (`sub`): PayPal's user ID (from userinfo)
   - **Audience** (`aud`): The PayPal app's `client_id`
   - **Nonce**: Tracked through the authorize→callback flow
   - **Signing**: HS256 with `client_secret` (per OIDC spec section 10.1)
4. Inject the `id_token` into the response before `openid-client` processes it

The synthetic `id_token` contains **only data that PayPal itself provided** through its userinfo endpoint. No claims are fabricated.

**Nonce tracking**

The OIDC `nonce` parameter is required in the `id_token` for replay protection. Since the bridge proxies the auth flow, it tracks the nonce through two maps:

```
authorize request → _nonceByState[state] = nonce
PayPal callback   → _nonceByCode[code] = _nonceByState[state]
token exchange    → id_token.nonce = _nonceByCode[code]
```

---

### Problem 3 (Resolved via configuration): Userinfo Endpoint Incompatibility

PayPal has **two separate** userinfo endpoints:

| Endpoint | Accepts tokens from |
|---|---|
| `/v1/identity/openidconnect/userinfo` | Legacy OIDC token endpoint (`/v1/identity/openidconnect/tokenservice`) |
| `/v1/oauth2/token/userinfo` | OAuth 2.0 token endpoint (`/v1/oauth2/token`) |

Initially, the discovery document pointed to the legacy endpoint, which rejected our OAuth2 access tokens with `401 Unauthorized`. This was fixed by updating the discovery document's `userinfo_endpoint` to `/v1/oauth2/token/userinfo`. No code shim is needed for this — it's a configuration fix at the discovery level.

---

## Summary of Shims

| # | Problem | PayPal Behavior | OIDC Spec Expectation | Fix |
|---|---------|----------------|----------------------|-----|
| 1 | `invalid_client` | Only accepts `client_secret_basic` | `openid-client` sends `client_secret_post` | Move credentials to `Authorization: Basic` header |
| 2 | Missing `id_token` | `/v1/oauth2/token` returns only `access_token` | `id_token` required when `openid` scope is requested | Fetch userinfo + synthesize HS256 JWT |
| 3 | Userinfo `401` | Legacy OIDC userinfo rejects OAuth2 tokens | Userinfo should accept any valid access token | Fixed by updating discovery doc `userinfo_endpoint` |

---

## What Data Comes From Where

```
PayPal userinfo (/v1/oauth2/token/userinfo):
  ├── sub (user_id)     → id_token.sub, Kratos identity ID
  ├── email             → id_token.email, Kratos traits.email
  ├── name              → id_token.name
  ├── given_name        → id_token.given_name
  └── family_name       → id_token.family_name

Synthetic id_token (HS256, signed with client_secret):
  ├── iss               → PayPal's origin (from discovery URL)
  ├── aud               → PayPal app client_id
  ├── iat/exp           → Current time / +1 hour
  └── nonce             → Tracked through authorize flow

Jackson's output to Kratos (RS256, signed with Jackson's RSA key):
  ├── Clean OIDC discovery at /.well-known/openid-configuration
  ├── Standard authorization_code grant
  ├── RS256 id_token with proper issuer
  └── Userinfo with normalized claims
```

---

## Production Considerations

1. **Replace HTTPS monkey-patching** — The current approach intercepts Node's `https.request`. In production, use a proper HTTP adapter layer or a custom `openid-client` configuration that supports PayPal's auth method.

2. **Token security** — The synthetic `id_token` is signed with `client_secret` (HS256). This is acceptable per OIDC spec (section 10.1 — symmetric key derived from client_secret), but it's only consumed internally by Jackson. Kratos never sees it — Jackson issues its own RS256-signed tokens.

3. **Nonce map cleanup** — The `_nonceByState` and `_nonceByCode` maps should have TTL-based expiry in production to prevent memory leaks from abandoned flows.

4. **Discovery document** — This POC uses a Postman mock for PayPal's sandbox discovery. In production, use PayPal's actual discovery URL (`https://www.paypalobjects.com/.well-known/openid-configuration`).

5. **Persistent database** — Jackson uses in-memory storage (`db: { engine: "mem" }`). Production should use PostgreSQL or another supported engine.

---

## Files

| File | Purpose |
|------|---------|
| `server.js` | Jackson OIDC bridge with PayPal compatibility shims |
| `.env` | PayPal app credentials (`PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`) |
| `kratos-paypal-oidc.yaml` | Kratos OIDC provider configuration snippet |
| `package.json` | Dependencies: `@boxyhq/saml-jackson`, `express`, `dotenv` |
