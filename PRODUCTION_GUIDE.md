# PayPal SAML SSO — Production Guide

## 1. Architecture Overview

```
                        SAML 2.0                      OIDC / OAuth 2.0
  ┌─────────────┐   (assertions)    ┌────────────┐   (tokens)      ┌──────────────┐
  │   PayPal     │◄────────────────►│  Jackson    │◄──────────────►│  Ory Kratos   │
  │   SAML IdP   │   POST to ACS    │  Bridge     │   authorize,   │  (Identity)   │
  │              │   AuthnRequest    │  (BoxyHQ)   │   token,       │              │
  │  paypal.com  │                  │  Owned by   │   userinfo     │  Owned by    │
  │  Owned by    │                  │  xFlowPay   │                │  xFlowPay    │
  │  PayPal      │                  │             │                │              │
  └──────┬───────┘                  └──────┬──────┘                └──────┬───────┘
         │                                 │                              │
         │   User authenticates            │  Translates                  │  Creates/links
         │   with PayPal creds             │  SAML ↔ OIDC                │  xFlowPay identity
         │                                 │                              │
         └─────────────── Browser ─────────┴──────────────────────────────┘
                         (redirects)
```

> **See `docs/flow.excalidraw` for an interactive version of this diagram.**

### What each component does

| Component | Owner | Protocol | Purpose |
|-----------|-------|----------|---------|
| PayPal SAML IdP | PayPal | SAML 2.0 | Authenticates users, issues SAML assertions |
| Jackson Bridge | xFlowPay | SAML ↔ OAuth/OIDC | Receives SAML, exposes OIDC endpoints for Kratos |
| Ory Kratos | xFlowPay | OIDC | Consumes OIDC to create/link user identities |

---

## 2. What PayPal needs to do

PayPal already runs a SAML 2.0 Identity Provider. They do **not** need to build anything new. They register xFlowPay as a **Service Provider (SP)** in their existing IdP.

### Information xFlowPay provides to PayPal

| Field | Value | Notes |
|-------|-------|-------|
| **ACS URL** | `https://jackson.xflowpay.com/sso/acs` | Where PayPal POSTs the SAML assertion |
| **Entity ID / Audience** | `https://saml.xflowpay.com` | Must match Jackson's `samlAudience` exactly |
| **NameID Format** | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` | User's email as the subject |

### Attribute mapping PayPal configures

| SAML Attribute | Meaning | Required |
|----------------|---------|----------|
| `email` | User's email address | Yes |
| `firstName` | First name | Yes |
| `lastName` | Last name | Yes |
| `displayName` | Full display name | Optional |

### What PayPal gives back to xFlowPay

| Artifact | How to obtain | Used for |
|----------|---------------|----------|
| **IdP Metadata XML** | URL or file download | Import into Jackson to create the SAML connection |
| **Signing Certificate** | Inside the metadata XML | Jackson uses it to verify assertion signatures |
| **SSO URL** | Inside the metadata XML | Where Jackson sends AuthnRequests |

### Key clarification: PayPal does NOT create a new IdP

PayPal's existing SAML IdP already serves many SPs (Okta, OneLogin, internal tools). Adding xFlowPay is just adding one more SP registration in their dashboard — same as how they'd add any enterprise partner.

```
PayPal SAML IdP (already exists)
 ├── SP: Okta (existing)
 ├── SP: Internal Tools (existing)
 └── SP: xFlowPay (new registration)  ← just this
        ACS URL: https://jackson.xflowpay.com/sso/acs
        Audience: https://saml.xflowpay.com
```

---

## 3. What xFlowPay needs to do

### 3.1 Deploy Jackson Bridge as a production service

**Replace the POC's in-memory setup with a production-grade deployment:**

```yaml
# docker-compose.yml (Jackson)
services:
  jackson:
    image: boxyhq/jackson:latest
    ports:
      - "5225:5225"
    environment:
      EXTERNAL_URL: https://jackson.xflowpay.com
      SAML_AUDIENCE: https://saml.xflowpay.com
      DB_ENGINE: sql
      DB_TYPE: postgres
      DB_URL: postgres://user:pass@db:5432/jackson
      JACKSON_API_KEYS: "<generate-a-secure-key>"
      CLIENT_SECRET_VERIFIER: "<generate-a-secure-secret>"
      NEXTAUTH_SECRET: "<generate-a-secret>"
      NEXTAUTH_URL: https://jackson.xflowpay.com
      OPENID_RSA_PRIVATE_KEY: "<base64-encoded-private-key>"
      OPENID_RSA_PUBLIC_KEY: "<base64-encoded-public-key>"
      IDP_ENABLED: "false"
      DO_NOT_TRACK: "1"
```

> When using the Jackson Docker image (vs. embedded npm library), it exposes all OIDC/OAuth endpoints automatically. No custom Express server needed.

### 3.2 Create the SAML connection (one-time setup)

Use Jackson's Admin API after receiving PayPal's IdP metadata:

```bash
curl -X POST https://jackson.xflowpay.com/api/v1/connections \
  -H "Authorization: Api-Key <your-jackson-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant": "paypal.com",
    "product": "xflowpay",
    "rawMetadata": "<paste PayPal IdP metadata XML here>",
    "redirectUrl": ["https://auth.xflowpay.com/*"],
    "defaultRedirectUrl": "https://auth.xflowpay.com/self-service/methods/oidc/callback/paypal-sso"
  }'
```

This returns `clientID` and `clientSecret` — use these in the Kratos config.

### 3.3 Configure Kratos

Add the PayPal SSO provider to your Kratos config:

```yaml
selfservice:
  methods:
    oidc:
      enabled: true
      config:
        providers:
          - id: paypal-sso
            provider: generic
            label: "PayPal SSO"
            client_id: "<clientID from Jackson>"
            client_secret: "<clientSecret from Jackson>"
            scope:
              - openid
              - email
              - profile
            issuer_url: https://jackson.xflowpay.com
            mapper_url: "base64://bG9jYWwgY2xhaW1zID0gewogIGVtYWlsX3ZlcmlmaWVkOiBmYWxzZSwKfSArIHN0ZC5leHRWYXIoJ2NsYWltcycpOwoKewoKICBpZGVudGl0eTogewogICAgdHJhaXRzOiB7CiAgICAgIFtpZiAnZW1haWwnIGluIGNsYWltcyB0aGVuICdlbWFpbCcgZWxzZSBudWxsXTogY2xhaW1zLmVtYWlsLAogICAgfSwKICAgIHZlcmlmaWVkX2FkZHJlc3Nlczogc3RkLnBydW5lKFsKICAgICAgaWYgJ2VtYWlsJyBpbiBjbGFpbXMgJiYgY2xhaW1zLmVtYWlsX3ZlcmlmaWVkIHRoZW4geyB2aWE6ICdlbWFpbCcsIHZhbHVlOiBjbGFpbXMuZW1haWwgfSwKICAgIF0pLAogIH0sCn0="
```

When using the Jackson Docker image, `issuer_url` is all that's needed — Kratos discovers `auth_url`, `token_url`, etc. from `/.well-known/openid-configuration` automatically.

### 3.4 DNS and TLS

| Domain | Points to | TLS |
|--------|-----------|-----|
| `jackson.xflowpay.com` | Jackson service | Required (HTTPS) |
| `auth.xflowpay.com` | Kratos public API | Required (HTTPS) |
| `app.xflowpay.com` | Frontend / login UI | Required (HTTPS) |

### 3.5 Generate stable OIDC signing keys

The POC generates RSA keys on every restart. In production, generate once and persist:

```bash
# Generate once
openssl genrsa -out jackson-private.pem 3072
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
  -in jackson-private.pem -out jackson-private-pkcs8.pem
openssl rsa -in jackson-private-pkcs8.pem -pubout -out jackson-public.pem

# Base64-encode for env vars
cat jackson-private-pkcs8.pem | base64  # → OPENID_RSA_PRIVATE_KEY
cat jackson-public.pem | base64          # → OPENID_RSA_PUBLIC_KEY
```

---

## 4. Authentication flow (production)

```
Step  Who → Where                          Protocol   What happens
─────────────────────────────────────────────────────────────────────────
 1    User → xFlowPay login page           HTTPS      Clicks "Login with PayPal"
 2    Browser → Kratos                      OIDC       Kratos initiates authorize redirect
 3    Browser → Jackson /api/oauth/authorize  OAuth    Jackson builds SAML AuthnRequest
 4    Browser → PayPal /saml/sso            SAML       User sees PayPal login page
 5    User authenticates at PayPal          SAML       PayPal verifies credentials
 6    PayPal → Jackson /sso/acs             SAML POST  Signed SAML assertion with user profile
 7    Jackson validates assertion           Internal   Signature check, audience check
 8    Jackson → Kratos callback             OAuth      Redirect with authorization code
 9    Kratos → Jackson /api/oauth/token     OIDC       Exchanges code + PKCE verifier for tokens
10    Kratos → Jackson /api/oauth/userinfo  OIDC       Fetches user profile (email, name)
11    Kratos creates/links identity         Internal   Upserts user in Kratos identity store
12    User is logged in to xFlowPay         Session    Kratos session cookie set
```

---

## 5. POC vs Production — gap analysis

### What the POC covers (sufficient)

| Aspect | Status |
|--------|--------|
| End-to-end SAML → OIDC flow | Working |
| Jackson as protocol bridge | Proven |
| Kratos OIDC integration with PKCE | Working |
| OIDC discovery (`.well-known`) | Working |
| User profile mapping (email, name) | Working |
| Attribute Statement extraction | Working |

### What needs to change for production

| POC Gap | Production Fix | Effort |
|---------|---------------|--------|
| In-memory DB (`engine: "mem"`) | PostgreSQL (`engine: "sql"`) | Low — just env vars |
| Keys generated on every restart | Stable persisted RSA keys | Low — one-time keygen |
| Mock SAML IdP | PayPal's real IdP metadata | Low — just swap metadata |
| HTTP / localhost | HTTPS with real domains | Medium — TLS + DNS |
| `samlAudience: "https://saml.boxyhq.com"` | `"https://saml.xflowpay.com"` | Low — config change |
| Embedded npm library | Jackson Docker image (recommended) | Medium — ops change |
| `client_secret: "dummy"` | Real `CLIENT_SECRET_VERIFIER` | Low — config change |
| No monitoring | Health checks, SSO Traces, alerting | Medium |
| `host.docker.internal` hacks | Same network / real DNS | Low — goes away with real domains |

### New problems you may face in production

| Problem | What happens | Mitigation |
|---------|-------------|------------|
| **PayPal cert rotation** | Assertion signature validation fails | Monitor metadata URL; Jackson supports re-importing metadata without downtime |
| **Clock skew** | SAML assertions rejected (`NotBefore`/`NotOnOrAfter`) | NTP sync on Jackson host; Jackson has configurable tolerance |
| **IdP-initiated login** | PayPal user clicks xFlowPay from PayPal dashboard (no AuthnRequest) | Set `IDP_ENABLED=true` in Jackson; configure `IDP_DISCOVERY_PATH` |
| **Multiple PayPal tenants** | E.g. PayPal US vs PayPal EU with different IdPs | Jackson natively supports multiple connections per tenant |
| **User deprovisioning** | PayPal disables a user, but they still have a Kratos session | Use SCIM directory sync (Jackson supports it) or short session TTLs |
| **Encrypted assertions** | PayPal encrypts SAML assertions (common in enterprise) | Provide Jackson's public key to PayPal; set `encryptionCert` in connection |
| **Rate limits** | PayPal may throttle SSO redirects under load | Unlikely, but add exponential backoff on the login UI |

---

## 6. Security checklist

- [ ] TLS on all endpoints (Jackson, Kratos, frontend)
- [ ] `CLIENT_SECRET_VERIFIER` set to a cryptographically random value
- [ ] `JACKSON_API_KEYS` set — Admin API is not open
- [ ] `SAML_AUDIENCE` set to your own domain (e.g., `https://saml.xflowpay.com`)
- [ ] OIDC signing keys generated with RSA 3072+ and stored in secrets manager
- [ ] Jackson database encrypted at rest (`DB_ENCRYPTION_KEY` set)
- [ ] SAML assertion signatures validated (Jackson does this by default)
- [ ] Redirect URLs whitelist is tight (no wildcards like `*` in production)
- [ ] Kratos session TTL configured appropriately
- [ ] SSO Traces enabled for debugging (`SSO_TRACES_DISABLE=false`)
- [ ] `NEXTAUTH_ACL` set for Jackson admin portal access

---

## 7. One-page summary for PayPal

> Send this to PayPal's IT/SSO team.

**Subject: SAML SSO Configuration Request for xFlowPay**

xFlowPay requests SAML 2.0 SSO integration with PayPal's Identity Provider.

**Service Provider Details:**

| Field | Value |
|-------|-------|
| SP Entity ID (Audience) | `https://saml.xflowpay.com` |
| ACS URL (POST binding) | `https://jackson.xflowpay.com/sso/acs` |
| NameID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| Assertion Signing | Required |
| Assertion Encryption | Optional (we support it) |

**Required Attributes:**

| Attribute Name | Description |
|---------------|-------------|
| `email` | User email (required) |
| `firstName` | User first name (required) |
| `lastName` | User last name (required) |

**What we need from PayPal:**
1. IdP Metadata XML (URL or file)
2. Confirmation of the attribute names in their assertion

That's it. No SDK, no library, no code changes on PayPal's side.
