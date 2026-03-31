const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const PORT = 5225;
const BASE_URL = `http://localhost:${PORT}`;
const DOCKER_URL = `http://host.docker.internal:${PORT}`;
const IDP_METADATA_URL = "http://localhost:7001/metadata";
const TENANT = "paypal.com";
const PRODUCT = "xflowpay";
const DEMO_REDIRECT_URL = `${BASE_URL}/sso/callback`;
const KRATOS_CALLBACK =
  "http://127.0.0.1:4433/self-service/methods/oidc/callback/paypal-sso";
const SAML_PATH = "/sso/acs";

let oauthController;
let connectionController;
let oidcDiscoveryController;
let connectionInfo;

// RSA keys for OpenID JWT signing (generated once at startup)
const { publicKey: rsaPubPem, privateKey: rsaPrivPem } =
  crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

async function fetchWithRetry(url, maxRetries = 15, delayMs = 2000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url);
      if (response.ok) return response;
    } catch (_) {
      // IdP not ready yet
    }
    if (i === 0) console.log("  Waiting for PayPal IdP to be available...");
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  throw new Error(
    `Failed to reach ${url} after ${maxRetries} attempts. Is the PayPal IdP running on port 7001?`,
  );
}

async function init() {
  console.log("\n========================================");
  console.log("  Jackson SAML-to-OIDC Bridge");
  console.log("========================================\n");

  const pubB64 = Buffer.from(rsaPubPem).toString("base64");
  const privB64 = Buffer.from(rsaPrivPem).toString("base64");

  console.log("[1/3] Initializing BoxyHQ Jackson (with OpenID support)...");
  const controllers = await require("@boxyhq/saml-jackson").controllers({
    externalUrl: DOCKER_URL,
    samlAudience: "https://saml.boxyhq.com",
    samlPath: SAML_PATH,
    acsUrl: `${BASE_URL}${SAML_PATH}`,
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

  console.log("[2/3] Fetching PayPal IdP metadata...");
  const metadataResponse = await fetchWithRetry(IDP_METADATA_URL);
  const metadata = await metadataResponse.text();
  console.log("       IdP metadata fetched\n");

  console.log("[3/3] Creating SAML connection...");
  connectionInfo = await connectionController.createSAMLConnection({
    tenant: TENANT,
    product: PRODUCT,
    rawMetadata: metadata,
    redirectUrl: [
      `${BASE_URL}/*`,
      "http://127.0.0.1:4433/*",
      "http://localhost:4433/*",
      "http://host.docker.internal:4433/*",
    ],
    defaultRedirectUrl: DEMO_REDIRECT_URL,
  });
  console.log("       SAML connection created");
  console.log(`       Tenant:       ${TENANT}`);
  console.log(`       Product:      ${PRODUCT}`);
  console.log(`       Client ID:    ${connectionInfo.clientID}`);
  console.log(`       Redirect URLs: demo + kratos\n`);

  app.listen(PORT, () => {
    console.log("========================================");
    console.log(`  Demo App:          ${BASE_URL}`);
    console.log(
      `  OIDC Discovery:    ${BASE_URL}/.well-known/openid-configuration`,
    );
    console.log(`  Authorize:         ${BASE_URL}/api/oauth/authorize`);
    console.log(`  Token:             ${BASE_URL}/api/oauth/token`);
    console.log(`  UserInfo:          ${BASE_URL}/api/oauth/userinfo`);
    console.log(`  ACS (SAML):        ${BASE_URL}${SAML_PATH}`);
    console.log("========================================");
    console.log(`\n  Open ${BASE_URL} in your browser to test`);
    console.log(`  Kratos can connect via issuer_url: ${BASE_URL}\n`);
  });
}

// ═══════════════════════════════════════════════════════════════
// OIDC Discovery & JWKS (used by Kratos to discover endpoints)
// ═══════════════════════════════════════════════════════════════

app.get("/.well-known/openid-configuration", async (req, res) => {
  // Server-to-server URLs use the requesting Host (so Docker → host.docker.internal works).
  // authorization_endpoint MUST use localhost — the browser handles that redirect.
  const serverOrigin = `${req.protocol}://${req.get("host")}`;
  const browserOrigin = BASE_URL; // always http://localhost:5225

  let base = {};
  try {
    if (oidcDiscoveryController?.openidConfig) {
      base = await oidcDiscoveryController.openidConfig();
    }
  } catch (_) {
    // use defaults
  }
  res.json({
    ...base,
    issuer: serverOrigin,
    authorization_endpoint: `${browserOrigin}/api/oauth/authorize`,
    token_endpoint: `${serverOrigin}/api/oauth/token`,
    userinfo_endpoint: `${serverOrigin}/api/oauth/userinfo`,
    jwks_uri: `${serverOrigin}/oauth/jwks`,
    response_types_supported: base.response_types_supported || ["code"],
    subject_types_supported: base.subject_types_supported || ["public"],
    id_token_signing_alg_values_supported:
      base.id_token_signing_alg_values_supported || ["RS256"],
    grant_types_supported: base.grant_types_supported || ["authorization_code"],
    code_challenge_methods_supported: base.code_challenge_methods_supported || [
      "plain",
      "S256",
    ],
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
      const jwks = await oidcDiscoveryController.jwks();
      return res.json(jwks);
    }
  } catch (_) {
    // fallback to manual
  }
  const jwk = crypto.createPublicKey(rsaPubPem).export({ format: "jwk" });
  res.json({ keys: [{ ...jwk, alg: "RS256", use: "sig", kid: "jackson-1" }] });
}

app.get("/oauth/jwks", jwksHandler);
app.get("/.well-known/jwks.json", jwksHandler);

// ═══════════════════════════════════════════════════════════════
// OAuth 2.0 HTTP Endpoints (used by Kratos server-to-server)
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
    res.redirect(redirect_url);
  } catch (err) {
    console.error("OAuth authorize error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/oauth/token", async (req, res) => {
  try {
    let { code, grant_type, redirect_uri, client_id, client_secret, code_verifier } =
      req.body;

    // Support Basic auth header (some OIDC clients send credentials this way)
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

    if (!token) {
      return res.status(401).json({ error: "Missing access token" });
    }

    const user = await oauthController.userInfo(token);

    // Return OIDC-compatible claims (Kratos expects standard claim names)
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
// SAML ACS — receives SAML assertion from PayPal IdP
// ═══════════════════════════════════════════════════════════════

app.post(SAML_PATH, async (req, res) => {
  try {
    const { SAMLResponse, RelayState } = req.body;
    const { redirect_url } = await oauthController.samlResponse({
      SAMLResponse,
      RelayState,
    });
    res.redirect(redirect_url);
  } catch (err) {
    console.error("SAML response error:", err);
    res.status(500).send(errorHTML("SAML Processing Failed", err.message));
  }
});

// ═══════════════════════════════════════════════════════════════
// Demo App (standalone testing without Kratos)
// ═══════════════════════════════════════════════════════════════

app.get("/", (_req, res) => res.send(landingHTML()));

app.get("/sso/login", async (req, res) => {
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
    console.error("Demo login error:", err);
    res.status(500).send(errorHTML("Authorization Failed", err.message));
  }
});

app.get("/sso/callback", async (req, res) => {
  try {
    const { code } = req.query;
    if (!code)
      return res
        .status(400)
        .send(errorHTML("Missing Code", "No authorization code received"));

    const { access_token } = await oauthController.token({
      code,
      client_id: `tenant=${TENANT}&product=${PRODUCT}`,
      client_secret: "dummy",
      redirect_uri: DEMO_REDIRECT_URL,
    });

    const user = await oauthController.userInfo(access_token);
    res.send(profileHTML(user));
  } catch (err) {
    console.error("Demo callback error:", err);
    res.status(500).send(errorHTML("Token Exchange Failed", err.message));
  }
});

// ═══════════════════════════════════════════════════════════════
// HTML Templates
// ═══════════════════════════════════════════════════════════════

function baseStyle() {
  return `* { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { background: white; padding: 48px; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); max-width: 560px; width: 100%; }
    a { color: #0070ba; }`;
}

function landingHTML() {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Xflowpay SSO Demo</title>
<style>
  ${baseStyle()}
  h1 { font-size: 22px; color: #1a1a2e; margin-bottom: 6px; }
  .sub { color: #777; margin-bottom: 32px; font-size: 14px; }
  .sso-btn { display: inline-flex; align-items: center; gap: 12px; background: #0070ba; color: white; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-size: 16px; font-weight: 600; transition: background 0.2s; }
  .sso-btn:hover { background: #005ea6; color: white; }
  .steps { margin-top: 32px; padding-top: 24px; border-top: 1px solid #eee; }
  .step { display: flex; gap: 10px; margin-bottom: 12px; font-size: 13px; color: #555; }
  .num { background: #e8f4fd; color: #0070ba; min-width: 22px; height: 22px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 11px; }
  .arch { margin-top: 20px; padding: 14px; background: #f8f9fa; border-radius: 8px; font-family: 'SF Mono', monospace; font-size: 11px; line-height: 1.8; color: #555; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 4px; }
  .tag-saml { background: #fff3cd; color: #856404; }
  .tag-oauth { background: #d4edda; color: #155724; }
  .tag-kratos { background: #e8daef; color: #6c3483; }
  .modes { margin-top: 24px; padding: 16px; background: #f0f4ff; border-radius: 8px; font-size: 13px; }
  .modes b { color: #333; }
</style></head>
<body><div class="container" style="text-align:center">
  <h1>Xflowpay Portal</h1>
  <p class="sub">Enterprise Single Sign-On via PayPal <span class="tag tag-saml">SAML 2.0</span></p>
  <a href="/sso/login" class="sso-btn">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="white"><path d="M7.076 21.337H2.47a.641.641 0 0 1-.633-.74L4.944 3.72a.77.77 0 0 1 .76-.654h6.554c2.174 0 3.686.457 4.49 1.358.378.422.615.891.71 1.392.1.525.093 1.152-.023 1.92l-.012.073v.636l.497.283c.42.225.754.487 1.004.788.339.406.553.91.635 1.498.085.606.034 1.308-.148 2.085a6.946 6.946 0 0 1-.81 2.092 4.57 4.57 0 0 1-1.283 1.382c-.49.354-1.073.62-1.733.79-.64.167-1.375.252-2.183.252h-.518a1.563 1.563 0 0 0-1.543 1.315l-.039.199-.659 4.17-.03.144a.097.097 0 0 1-.097.084H7.076Z"/></svg>
    Login with PayPal SSO
  </a>
  <div class="modes">
    <b>Two test modes:</b><br>
    1. <b>Standalone</b> — click the button above (direct Jackson flow)<br>
    2. <b>Via Kratos</b> — use Kratos login UI at <code>http://127.0.0.1:4433</code> <span class="tag tag-kratos">OIDC</span>
  </div>
  <div class="steps" style="text-align:left">
    <p style="font-size:13px;font-weight:600;color:#333;margin-bottom:14px">Kratos Integration Flow</p>
    <div class="step"><span class="num">1</span><span>Kratos redirects to Jackson <span class="tag tag-oauth">OAuth 2.0</span></span></div>
    <div class="step"><span class="num">2</span><span>Jackson generates <b>SAML AuthnRequest</b> &rarr; PayPal IdP <span class="tag tag-saml">SAML</span></span></div>
    <div class="step"><span class="num">3</span><span>User authenticates at <b>PayPal</b> (mock IdP on port 7001)</span></div>
    <div class="step"><span class="num">4</span><span>PayPal posts <b>SAML Assertion</b> &rarr; Jackson ACS <span class="tag tag-saml">SAML</span></span></div>
    <div class="step"><span class="num">5</span><span>Jackson issues <b>authorization code</b> &rarr; Kratos callback <span class="tag tag-oauth">OAuth</span></span></div>
    <div class="step"><span class="num">6</span><span>Kratos exchanges code for <b>token + userinfo</b> &rarr; creates identity <span class="tag tag-kratos">Kratos</span></span></div>
    <div class="arch">
      Browser &rarr; Kratos &rarr; Jackson (authorize) &rarr; PayPal SAML IdP<br>
      PayPal &rarr; Jackson (ACS) &rarr; Kratos (callback + code)<br>
      Kratos &rarr; Jackson (token + userinfo) &rarr; Identity Created
    </div>
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
<html><head><meta charset="utf-8"><title>Profile - PayPal SSO</title>
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
  <div class="ok">Authenticated via PayPal SAML SSO through Jackson Bridge</div>
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
  console.error("\nFailed to initialize:\n", err.message);
  console.error(
    "\nMake sure the PayPal SAML IdP is running on port 7001 first.",
  );
  process.exit(1);
});
