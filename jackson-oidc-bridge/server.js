require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const https = require("https");

// ══════════════════════════════════════════════════════════════════════
// PayPal OIDC Compatibility Layer
// ══════════════════════════════════════════════════════════════════════
//
// PayPal's OIDC implementation deviates from spec in ways that break
// openid-client (used internally by Jackson). This layer patches three
// specific incompatibilities at the HTTPS transport level:
//
//   1. AUTH METHOD — PayPal requires client_secret_basic (credentials
//      in Authorization header), but openid-client sends them as
//      client_secret_post (in the request body). We move them.
//
//   2. MISSING id_token — PayPal's /v1/oauth2/token returns only an
//      access_token; openid-client expects an id_token. We fetch the
//      user's profile from PayPal's userinfo API and construct a
//      conformant id_token (HS256-signed with client_secret).
//
//   3. USERINFO ENDPOINT — Tokens from /v1/oauth2/token are rejected
//      by PayPal's legacy OIDC userinfo (/v1/identity/openidconnect/).
//      We redirect those calls to /v1/identity/oauth2/userinfo which
//      accepts standard OAuth2 bearer tokens.
//
// NOTE: This monkey-patching approach is acceptable for a POC. In
// production, replace with a proper HTTP adapter or use a PayPal-aware
// OIDC client library.
// ══════════════════════════════════════════════════════════════════════

const _origRequest = https.request;
const _nonceByState = new Map();
const _nonceByCode = new Map();

function createHS256JWT(payload, secret) {
  const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${sig}`;
}

function fetchPayPalUserInfo(accessToken, hostname) {
  return new Promise((resolve, reject) => {
    const req = _origRequest(
      {
        hostname,
        path: "/v1/identity/oauth2/userinfo?schema=openid",
        method: "GET",
        headers: {
          authorization: `Bearer ${accessToken}`,
          accept: "application/json",
        },
      },
      (res) => {
        let d = "";
        res.on("data", (c) => (d += c));
        res.on("end", () => {
          if (res.statusCode >= 400) {
            reject(new Error(`PayPal userinfo ${res.statusCode}: ${d.substring(0, 200)}`));
            return;
          }
          try {
            const json = JSON.parse(d);
            json.sub = json.sub || json.user_id || json.payer_id;
            resolve(json);
          } catch (e) {
            reject(new Error(`PayPal userinfo parse error: ${d.substring(0, 200)}`));
          }
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

https.request = function (options, callback) {
  if (typeof options !== "object" || !options.hostname?.includes("paypal")) {
    return _origRequest.call(this, options, callback);
  }

  // Shim 3: redirect legacy OIDC userinfo → OAuth2 userinfo
  if (options.path?.includes("/openidconnect/userinfo")) {
    options.path = options.path.replace(
      "/v1/identity/openidconnect/userinfo",
      "/v1/identity/oauth2/userinfo",
    );
    return _origRequest.call(this, options, callback);
  }

  // Shims 1 + 2 only apply to the token endpoint
  if (!options.path?.includes("/oauth2/token")) {
    return _origRequest.call(this, options, callback);
  }

  let requestCode;

  const wrappedCb = (res) => {
    const chunks = [];
    const realHandlers = {};
    const origOn = res.on.bind(res);

    res.on = function (event, handler) {
      if (event === "data") {
        realHandlers.data = handler;
        return origOn("data", (chunk) => chunks.push(chunk));
      }
      if (event === "end") {
        realHandlers.end = handler;
        return origOn("end", async () => {
          let body = Buffer.concat(chunks).toString();
          try {
            const json = JSON.parse(body);
            // Shim 2: synthesize id_token when PayPal omits it
            if (res.statusCode === 200 && json.access_token && !json.id_token) {
              const userInfo = await fetchPayPalUserInfo(json.access_token, options.hostname);
              const nonce = requestCode ? _nonceByCode.get(requestCode) : undefined;
              if (requestCode) _nonceByCode.delete(requestCode);

              const issuer = new URL(PAYPAL_DISCOVERY[PAYPAL_ENV]).origin;
              const now = Math.floor(Date.now() / 1000);
              json.id_token = createHS256JWT(
                {
                  iss: issuer,
                  sub: userInfo.sub,
                  aud: PAYPAL_CLIENT_ID,
                  iat: now,
                  exp: now + 3600,
                  ...(nonce ? { nonce } : {}),
                  email: userInfo.email,
                  name: userInfo.name,
                  given_name: userInfo.given_name,
                  family_name: userInfo.family_name,
                },
                PAYPAL_CLIENT_SECRET,
              );
              body = JSON.stringify(json);
            }
          } catch (e) {
            console.error("[paypal-compat] id_token synthesis failed:", e.message);
          }
          if (realHandlers.data) realHandlers.data(body);
          if (realHandlers.end) realHandlers.end();
        });
      }
      return origOn(event, handler);
    };
    if (callback) callback(res);
  };

  const req = _origRequest.call(this, options, wrappedCb);
  const _origWrite = req.write.bind(req);

  // Shim 1: move client credentials from POST body to Authorization: Basic
  req.write = function (data) {
    const bodyStr = data?.toString?.() || "";
    const params = new URLSearchParams(bodyStr);
    requestCode = params.get("code");
    const clientId = params.get("client_id");
    const clientSecret = params.get("client_secret");

    if (clientId && clientSecret && !options.headers?.authorization) {
      req.setHeader("authorization", `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`);
      params.delete("client_id");
      params.delete("client_secret");
      return _origWrite(params.toString());
    }
    return _origWrite(data);
  };

  return req;
};

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── Config ────────────────────────────────────────────────────

const PORT = 5225;
const BASE_URL = `http://local.xflowpay.com:${PORT}`;

const TENANT = "paypal.com";
const PRODUCT = "xflowpay";
const DEMO_REDIRECT_URL = `${BASE_URL}/sso/callback`;
const OIDC_PATH = "/api/oauth/oidc";

const PAYPAL_ENV = process.env.PAYPAL_ENV || "sandbox";
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

const PAYPAL_DISCOVERY = {
  sandbox: "https://b5755142-d32e-4e05-898f-cf0bf7632d20.mock.pstmn.io/.well-known/openid-configuration",
  live: "https://www.paypalobjects.com/.well-known/openid-configuration",
};

let oauthController;
let connectionController;
let oidcDiscoveryController;
let connectionInfo;

// Stable RSA keys for OpenID JWT signing (generated once at startup)
const { publicKey: rsaPubPem, privateKey: rsaPrivPem } =
  crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

// ── Init ──────────────────────────────────────────────────────

async function init() {
  console.log("\n================================================");
  console.log("  Jackson OIDC Bridge — PayPal → Kratos");
  console.log("================================================\n");

  if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
    console.error(
      "ERROR: PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must be set.\n" +
        "  1. Copy .env.example to .env\n" +
        "  2. Fill in your PayPal Developer app credentials\n" +
        '  3. Make sure "Log in with PayPal" is enabled in the app settings\n' +
        `  4. Add this Return URL to your PayPal app: ${BASE_URL}${OIDC_PATH}\n`,
    );
    process.exit(1);
  }

  const pubB64 = Buffer.from(rsaPubPem).toString("base64");
  const privB64 = Buffer.from(rsaPrivPem).toString("base64");

  console.log("[1/3] Initializing BoxyHQ Jackson (OIDC mode)...");
  const controllers = await require("@boxyhq/saml-jackson").controllers({
    externalUrl: BASE_URL,
    samlAudience: "https://saml.xflowpay.com",
    samlPath: "/sso/acs",
    oidcPath: OIDC_PATH,
    db: { engine: "mem" },
    openid: {
      jwsAlg: "RS256",
      jwtSigningKeys: { private: privB64, public: pubB64 },
    },
  });

  oauthController = controllers.oauthController;
  connectionController = controllers.connectionAPIController;
  oidcDiscoveryController = controllers.oidcDiscoveryController;
  console.log("       Jackson initialized (in-memory DB + OpenID)\n");

  const discoveryUrl = PAYPAL_DISCOVERY[PAYPAL_ENV];

  console.log(`[2/3] Creating PayPal OIDC connection (${PAYPAL_ENV})...`);
  console.log(`       Discovery: ${discoveryUrl}`);
  connectionInfo = await connectionController.createOIDCConnection({
    tenant: TENANT,
    product: PRODUCT,
    redirectUrl: [
      `${BASE_URL}/*`,
      "http://127.0.0.1:4433/*",
      "http://localhost:4433/*",
      "http://local.xflowpay.com:4433/*",
    ],
    defaultRedirectUrl: DEMO_REDIRECT_URL,
    oidcDiscoveryUrl: PAYPAL_DISCOVERY[PAYPAL_ENV],
    oidcClientId: PAYPAL_CLIENT_ID,
    oidcClientSecret: PAYPAL_CLIENT_SECRET,
  });
  console.log("       PayPal OIDC connection created");
  console.log(`       Tenant:    ${TENANT}`);
  console.log(`       Product:   ${PRODUCT}`);
  console.log(`       Client ID: ${connectionInfo.clientID}\n`);
  console.log(`       Client Secret: ${connectionInfo.clientSecret}`);

  console.log("[3/3] Starting server...");
  app.listen(PORT, () => {
    console.log(`\nJackson OIDC Bridge running on ${BASE_URL}`);
    console.log(`  PayPal env:      ${PAYPAL_ENV}`);
    console.log(`  OIDC Discovery:  ${BASE_URL}/.well-known/openid-configuration`);
    console.log(`  PayPal callback: ${BASE_URL}${OIDC_PATH}\n`);
  });
}

// ═══════════════════════════════════════════════════════════════
// OIDC Discovery & JWKS — what Kratos uses to discover endpoints
// Jackson issues its own clean RS256 id_tokens to Kratos
// ═══════════════════════════════════════════════════════════════

app.get("/.well-known/openid-configuration", async (req, res) => {
  let base = {};
  try {
    if (oidcDiscoveryController?.openidConfig) {
      base = await oidcDiscoveryController.openidConfig();
    }
  } catch (_) {}

  res.json({
    ...base,
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/api/oauth/authorize`,
    token_endpoint: `${BASE_URL}/api/oauth/token`,
    userinfo_endpoint: `${BASE_URL}/api/oauth/userinfo`,
    jwks_uri: `${BASE_URL}/oauth/jwks`,
    response_types_supported: base.response_types_supported || ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["plain", "S256"],
    scopes_supported: ["openid", "email", "profile"],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic",
    ],
    claims_supported: ["sub", "email", "name", "given_name", "family_name"],
  });
});

async function jwksHandler(_req, res) {
  try {
    if (oidcDiscoveryController?.jwks) {
      return res.json(await oidcDiscoveryController.jwks());
    }
  } catch (_) {}
  const jwk = crypto.createPublicKey(rsaPubPem).export({ format: "jwk" });
  res.json({ keys: [{ ...jwk, alg: "RS256", use: "sig", kid: "jackson-1" }] });
}

app.get("/oauth/jwks", jwksHandler);
app.get("/.well-known/jwks.json", jwksHandler);

// ═══════════════════════════════════════════════════════════════
// OAuth 2.0 Endpoints — Kratos talks to these (server-to-server)
// ═══════════════════════════════════════════════════════════════

app.get("/api/oauth/authorize", async (req, res) => {
  try {
    const {
      client_id,
      redirect_uri,
      state,
      response_type,
      scope,
      nonce,
      code_challenge,
      code_challenge_method,
    } = req.query;

    const params = {
      client_id: client_id || `tenant=${TENANT}&product=${PRODUCT}`,
      state,
      redirect_uri,
      response_type: response_type || "code",
      scope,
      nonce,
    };

    if (code_challenge) {
      params.code_challenge = code_challenge;
      params.code_challenge_method = code_challenge_method;
    }

    const { redirect_url } = await oauthController.authorize(params);

    // Track nonce for id_token synthesis (shim 2)
    try {
      const paypalUrl = new URL(redirect_url);
      const oidcNonce = paypalUrl.searchParams.get("nonce");
      const oidcState = paypalUrl.searchParams.get("state");
      if (oidcNonce && oidcState) _nonceByState.set(oidcState, oidcNonce);
    } catch (_) {}

    res.redirect(redirect_url);
  } catch (err) {
    console.error("OAuth authorize error:", err);
    res.status(400).json({ error: err.message });
  }
});

// PayPal redirects here after user authenticates
app.get(OIDC_PATH, async (req, res) => {
  try {
    const { code, state } = req.query;

    // Transfer nonce from state→code for id_token synthesis (shim 2)
    const nonce = _nonceByState.get(state);
    if (nonce && code) {
      _nonceByCode.set(code, nonce);
      _nonceByState.delete(state);
    }

    const { redirect_url } = await oauthController.oidcAuthzResponse({ code, state });
    res.redirect(redirect_url);
  } catch (err) {
    console.error("PayPal OIDC callback error:", err);
    res.status(500).send(errorHTML("PayPal OIDC Callback Failed", err.message));
  }
});

app.post("/api/oauth/token", async (req, res) => {
  try {
    let {
      code,
      grant_type,
      redirect_uri,
      client_id,
      client_secret,
      code_verifier,
    } = req.body;

    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith("Basic ")) {
      const decoded = Buffer.from(authHeader.slice(6), "base64").toString();
      const colonIdx = decoded.indexOf(":");
      if (colonIdx > -1) {
        client_id = client_id || decoded.slice(0, colonIdx);
        client_secret = client_secret || decoded.slice(colonIdx + 1);
      }
    }

    const tokenResponse = await oauthController.token({
      code,
      client_id: client_id || `tenant=${TENANT}&product=${PRODUCT}`,
      client_secret: client_secret || "dummy",
      redirect_uri,
      grant_type: grant_type || "authorization_code",
      code_verifier,
    });

    res.json(tokenResponse);
  } catch (err) {
    console.error("OAuth token error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/oauth/userinfo", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "") || req.query.access_token;
    if (!token) return res.status(401).json({ error: "Missing access token" });

    const user = await oauthController.userInfo(token);

    res.json({
      sub: user.id,
      email: user.email,
      email_verified: true,
      given_name: user.firstName,
      family_name: user.lastName,
      name: [user.firstName, user.lastName].filter(Boolean).join(" "),
      ...user.raw,
    });
  } catch (err) {
    console.error("OAuth userinfo error:", err);
    res.status(401).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// Demo App — standalone testing without Kratos
// ═══════════════════════════════════════════════════════════════

app.get("/", (_req, res) => res.send(landingHTML()));

app.get("/sso/login", async (_req, res) => {
  try {
    const state = crypto.randomBytes(16).toString("hex");
    const { redirect_url } = await oauthController.authorize({
      tenant: TENANT,
      product: PRODUCT,
      state,
      redirect_uri: DEMO_REDIRECT_URL,
      response_type: "code",
    });
    res.redirect(redirect_url);
  } catch (err) {
    res.status(500).send(errorHTML("Authorization Failed", err.message));
  }
});

app.get("/sso/callback", async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) {
      return res
        .status(400)
        .send(errorHTML("Missing Code", "No authorization code received"));
    }

    const { access_token } = await oauthController.token({
      code,
      client_id: `tenant=${TENANT}&product=${PRODUCT}`,
      client_secret: "dummy",
      redirect_uri: DEMO_REDIRECT_URL,
    });

    const user = await oauthController.userInfo(access_token);
    res.send(profileHTML(user));
  } catch (err) {
    res.status(500).send(errorHTML("Token Exchange Failed", err.message));
  }
});

// ═══════════════════════════════════════════════════════════════
// HTML Templates
// ═══════════════════════════════════════════════════════════════

function baseStyle() {
  return `* { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { background: white; padding: 48px; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); max-width: 600px; width: 100%; }
    a { color: #0070ba; }`;
}

function landingHTML() {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Xflowpay — PayPal OIDC SSO</title>
<style>
  ${baseStyle()}
  h1 { font-size: 22px; color: #1a1a2e; margin-bottom: 6px; }
  .sub { color: #777; margin-bottom: 32px; font-size: 14px; }
  .sso-btn { display: inline-flex; align-items: center; gap: 12px; background: #0070ba; color: white; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-size: 16px; font-weight: 600; transition: background 0.2s; }
  .sso-btn:hover { background: #005ea6; color: white; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 4px; }
  .tag-oidc { background: #d4edda; color: #155724; }
  .tag-kratos { background: #e8daef; color: #6c3483; }
  .info { margin-top: 28px; padding: 16px; background: #f0f4ff; border-radius: 8px; font-size: 13px; text-align: left; line-height: 1.7; }
  .arch { margin-top: 20px; padding: 14px; background: #f8f9fa; border-radius: 8px; font-family: 'SF Mono', monospace; font-size: 11px; line-height: 1.8; color: #555; text-align: left; }
</style></head>
<body><div class="container" style="text-align:center">
  <h1>Xflowpay Portal</h1>
  <p class="sub">Login via PayPal <span class="tag tag-oidc">OIDC → Jackson → OIDC</span></p>
  <a href="/sso/login" class="sso-btn">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="white"><path d="M7.076 21.337H2.47a.641.641 0 0 1-.633-.74L4.944 3.72a.77.77 0 0 1 .76-.654h6.554c2.174 0 3.686.457 4.49 1.358.378.422.615.891.71 1.392.1.525.093 1.152-.023 1.92l-.012.073v.636l.497.283c.42.225.754.487 1.004.788.339.406.553.91.635 1.498.085.606.034 1.308-.148 2.085a6.946 6.946 0 0 1-.81 2.092 4.57 4.57 0 0 1-1.283 1.382c-.49.354-1.073.62-1.733.79-.64.167-1.375.252-2.183.252h-.518a1.563 1.563 0 0 0-1.543 1.315l-.039.199-.659 4.17-.03.144a.097.097 0 0 1-.097.084H7.076Z"/></svg>
    Login with PayPal
  </a>
  <div class="info">
    <b>How it works:</b> PayPal's OIDC is non-standard (HS256 tokens, mismatched issuer).
    Jackson normalizes it into clean RS256 OIDC that Kratos can consume.
  </div>
  <div class="arch">
    PayPal (quirky OIDC) &rarr; Jackson (normalizes) &rarr; Kratos (clean RS256)<br><br>
    1. Kratos/browser &rarr; Jackson <code>/api/oauth/authorize</code><br>
    2. Jackson &rarr; PayPal <code>/signin/authorize</code> (PayPal login page)<br>
    3. PayPal &rarr; Jackson <code>${OIDC_PATH}</code> (auth code)<br>
    4. Jackson exchanges code with PayPal, extracts profile<br>
    5. Jackson &rarr; Kratos callback (clean auth code)<br>
    6. Kratos &rarr; Jackson token + userinfo &rarr; identity created
  </div>
</div></body></html>`;
}

function profileHTML(user) {
  const fields = [
    ["ID", user.id],
    ["Email", user.email],
    ["First Name", user.firstName],
    ["Last Name", user.lastName],
    ["Tenant", user.requested?.tenant || TENANT],
    ["Product", user.requested?.product || PRODUCT],
  ];
  const rows = fields
    .map(
      ([k, v]) =>
        `<div class="field"><span class="label">${k}</span><span class="value">${v || "N/A"}</span></div>`,
    )
    .join("");
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Profile — PayPal OIDC SSO</title>
<style>
  ${baseStyle()}
  .ok { background: #d4edda; color: #155724; padding: 10px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; }
  h1 { font-size: 22px; color: #1a1a2e; margin-bottom: 20px; }
  .card { border: 1px solid #eee; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
  .field { display: flex; padding: 8px 0; border-bottom: 1px solid #f5f5f5; }
  .field:last-child { border-bottom: none; }
  .label { color: #888; font-size: 13px; width: 110px; flex-shrink: 0; }
  .value { color: #222; font-size: 14px; font-weight: 500; word-break: break-all; }
  .raw h3 { font-size: 13px; color: #888; margin-bottom: 8px; }
  .raw pre { background: #f8f9fa; padding: 14px; border-radius: 8px; font-size: 11px; overflow-x: auto; line-height: 1.5; }
  .back { display: inline-block; margin-top: 20px; font-size: 14px; }
</style></head>
<body><div class="container">
  <div class="ok">Authenticated via PayPal OIDC through Jackson Bridge</div>
  <h1>User Profile</h1>
  <div class="card">${rows}</div>
  <div class="raw"><h3>Raw Jackson Response</h3><pre>${JSON.stringify(user, null, 2)}</pre></div>
  <a href="/" class="back">&larr; Back to Home</a>
</div></body></html>`;
}

function errorHTML(title, detail) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Error</title>
<style>
  ${baseStyle()}
  .err { background: #f8d7da; color: #721c24; padding: 10px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
  pre { background: #f8f9fa; padding: 14px; border-radius: 8px; font-size: 12px; overflow-x: auto; margin-bottom: 16px; white-space: pre-wrap; }
</style></head>
<body><div class="container">
  <div class="err">${title}</div>
  <pre>${detail}</pre>
  <a href="/">&larr; Back to Home</a>
</div></body></html>`;
}

// ── Boot ──────────────────────────────────────────────────────

init().catch((err) => {
  console.error("Failed to initialize:", err.message);
  process.exit(1);
});
