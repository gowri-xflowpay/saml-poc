# Jackson OIDC Bridge — PayPal → Kratos

Normalizes PayPal's non-standard OIDC into clean RS256 OIDC that Kratos can consume.

## Why this exists

PayPal's OIDC has quirks that break Kratos's strict `generic` OIDC provider:

| Problem | Detail |
|---------|--------|
| HS256 id_tokens | PayPal may sign tokens with HMAC (symmetric), Kratos expects RS256 (asymmetric) |
| Issuer mismatch | Discovery at `paypalobjects.com`, issuer claims `paypal.com` |
| Non-standard userinfo | Path includes `/token/` and requires `?schema=openid` |

Jackson absorbs these quirks and presents clean, standards-compliant OIDC to Kratos.

## Architecture

```
PayPal OIDC (quirky)  →  Jackson Bridge (normalizes)  →  Ory Kratos (clean RS256)
   HS256 tokens              RS256 re-signing              Standard OIDC consumer
   Weird discovery           Clean .well-known              Creates identities
```

## Setup

### 1. Create a PayPal Developer App

1. Go to [developer.paypal.com/dashboard/applications](https://developer.paypal.com/dashboard/applications)
2. Create or select a REST API app
3. Enable **"Log in with PayPal"** in app features
4. Select attributes: Email address, Full name
5. Add Return URL: `http://local.xflowpay.com:5225/api/oauth/oidc`
6. Note your **Client ID** and **Secret**

### 2. Configure and run

```bash
cd jackson-oidc-bridge
npm install
cp .env.example .env
# Edit .env with your PayPal credentials
npm start
```

### 3. Add to Kratos

Copy the provider config from `kratos-paypal-oidc.yaml` into your `kratos.yml` under `selfservice.methods.oidc.config.providers`.

### 4. Test

- **Standalone**: Open `http://local.xflowpay.com:5225` and click "Login with PayPal"
- **Via Kratos**: Use the PayPal SSO option on your Kratos login page

## Endpoints

| Endpoint | URL | Used by |
|----------|-----|---------|
| OIDC Discovery | `/.well-known/openid-configuration` | Kratos (auto-discovery) |
| Authorize | `/api/oauth/authorize` | Browser (redirect) |
| PayPal Callback | `/api/oauth/oidc` | PayPal (redirect back) |
| Token | `/api/oauth/token` | Kratos (server-to-server) |
| UserInfo | `/api/oauth/userinfo` | Kratos (server-to-server) |
| JWKS | `/oauth/jwks` | Kratos (JWT verification) |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PAYPAL_CLIENT_ID` | Yes | PayPal REST app Client ID |
| `PAYPAL_CLIENT_SECRET` | Yes | PayPal REST app Secret |
| `PAYPAL_ENV` | No | `sandbox` (default) or `live` |
