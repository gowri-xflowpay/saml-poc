# PayPal SAML SSO POC — BoxyHQ Jackson Bridge

Proof-of-concept demonstrating how **PayPal (acting as a SAML 2.0 Identity Provider)** can authenticate users into **Xflowpay** via a **BoxyHQ Jackson SAML-to-OAuth 2.0 bridge**.

## Architecture

```
┌──────────────┐  SAML AuthnReq   ┌──────────────────┐  OAuth authorize  ┌──────────────┐
│  PayPal SAML │ ◄──────────────── │  BoxyHQ Jackson   │ ◄──────────────── │  Xflowpay    │
│  IdP (mock)  │ ──────────────── ▶│  (SAML → OAuth)   │ ──────────────── ▶│  Demo App    │
│  Port 7001   │  SAML Assertion   │  Port 5225        │  Code + Token     │  (embedded)  │
└──────────────┘                   └──────────────────┘                   └──────────────┘
```

### Flow

1. User visits `http://localhost:5225` and clicks **"Login with PayPal SSO"**
2. Jackson generates a SAML AuthnRequest and redirects to the PayPal IdP
3. User authenticates at the PayPal IdP (mock on port 7001 — pre-filled test user)
4. PayPal IdP POSTs a SAML Assertion to Jackson's ACS endpoint
5. Jackson extracts the user profile, issues an OAuth authorization code
6. Demo app exchanges the code for an access token and fetches user info
7. User profile is displayed

## Folder Structure

```
paypal-sml-poc/
├── paypal-saml-idp/      # Mock PayPal SAML 2.0 Identity Provider
│   ├── package.json
│   └── server.js
├── jackson-bridge/        # BoxyHQ Jackson bridge + demo app
│   ├── package.json
│   └── server.js
├── start.sh               # Starts both servers
└── README.md
```

## Quick Start

```bash
# Install & run everything
./start.sh
```

Or manually:

```bash
# Terminal 1 — Start the PayPal SAML IdP
cd paypal-saml-idp
npm install
npm start

# Terminal 2 — Start Jackson Bridge + Demo App
cd jackson-bridge
npm install
npm start
```

Then open **http://localhost:5225** in your browser.

## Services

| Service | Port | Description |
|---------|------|-------------|
| PayPal SAML IdP | 7001 | Mock SAML 2.0 IdP simulating PayPal |
| Jackson Bridge | 5225 | SAML-to-OAuth 2.0 bridge + demo UI |

## Key Endpoints

### PayPal SAML IdP (port 7001)
- `GET /` — IdP web UI (review/edit SAML assertion before sending)
- `GET /metadata` — SAML IdP metadata XML
- `GET /saml/sso` — Single Sign-On endpoint (HTTP-Redirect)
- `POST /saml/sso` — Single Sign-On endpoint (HTTP-POST)

### Jackson Bridge (port 5225)
- `GET /` — Demo app landing page
- `GET /sso/login` — Initiates the SSO flow
- `POST /sso/acs` — Assertion Consumer Service (receives SAML assertion)
- `GET /sso/callback` — OAuth callback (exchanges code for token)

## Test User

| Field | Value |
|-------|-------|
| Email | paypal.merchant@xflowpay.com |
| First Name | PayPal |
| Last Name | Merchant |
| Display Name | PayPal Merchant User |

You can modify these values in the IdP web UI at `http://localhost:7001` before submitting.

## How Jackson Bridges SAML → OAuth

Jackson (by BoxyHQ, now Ory Polis) acts as a **protocol translator**:

1. **Receives** an OAuth 2.0 authorization request from the app (or Kratos)
2. **Generates** a SAML AuthnRequest and redirects to the IdP
3. **Receives** the SAML Assertion at its ACS endpoint
4. **Extracts** the user profile from the assertion
5. **Issues** an OAuth 2.0 authorization code back to the caller
6. The caller exchanges the code for an access token and retrieves user info

This means any app that speaks OAuth 2.0/OIDC can authenticate against a SAML IdP without implementing SAML directly.

## Integration with Ory Kratos

Jackson exposes standard OIDC endpoints that Kratos can discover and consume:

| Endpoint | URL |
|----------|-----|
| OIDC Discovery | `http://localhost:5225/.well-known/openid-configuration` |
| Authorization | `http://localhost:5225/api/oauth/authorize` |
| Token | `http://localhost:5225/api/oauth/token` |
| UserInfo | `http://localhost:5225/api/oauth/userinfo` |
| JWKS | `http://localhost:5225/oauth/jwks` |

### Step 1: Add the PayPal SSO provider to your `kratos.yml`

Under `selfservice.methods.oidc.config.providers`, add:

```yaml
- id: paypal-sso
  provider: generic
  label: "PayPal SSO"
  client_id: "tenant=paypal.com&product=xflowpay"
  client_secret: "dummy"
  scope:
    - openid
    - email
    - profile
  issuer_url: http://localhost:5225
  auth_url: http://localhost:5225/api/oauth/authorize
  token_url: http://localhost:5225/api/oauth/token
  mapper_url: "base64://bG9jYWwgY2xhaW1zID0gewogIGVtYWlsX3ZlcmlmaWVkOiBmYWxzZSwKfSArIHN0ZC5leHRWYXIoJ2NsYWltcycpOwoKewoKICBpZGVudGl0eTogewogICAgdHJhaXRzOiB7CiAgICAgIFtpZiAnZW1haWwnIGluIGNsYWltcyB0aGVuICdlbWFpbCcgZWxzZSBudWxsXTogY2xhaW1zLmVtYWlsLAogICAgfSwKICAgIHZlcmlmaWVkX2FkZHJlc3Nlczogc3RkLnBydW5lKFsKICAgICAgaWYgJ2VtYWlsJyBpbiBjbGFpbXMgJiYgY2xhaW1zLmVtYWlsX3ZlcmlmaWVkIHRoZW4geyB2aWE6ICdlbWFpbCcsIHZhbHVlOiBjbGFpbXMuZW1haWwgfSwKICAgIF0pLAogIH0sCn0="
```

### Step 2: Ensure Kratos can reach Jackson

If Kratos runs in Docker and Jackson on the host, use `host.docker.internal:5225` instead of `localhost:5225` in the URLs above.

If both run on the host, `localhost:5225` works as-is.

### Step 3: Start all services

```bash
# Terminal 1: PayPal IdP
cd paypal-saml-idp && npm start

# Terminal 2: Jackson Bridge
cd jackson-bridge && npm start

# Terminal 3: Kratos (however you normally start it)
```

### Flow with Kratos

```
Browser → Kratos (login UI) → Jackson (authorize) → PayPal SAML IdP
PayPal IdP → Jackson (ACS) → Kratos (callback + code)
Kratos → Jackson (token + userinfo) → Identity Created → Session
```

### Pre-built config

See `jackson-bridge/kratos-paypal-sso.yaml` for the ready-to-use provider config and `jackson-bridge/paypal-mapper.jsonnet` for the Jsonnet mapper source.
