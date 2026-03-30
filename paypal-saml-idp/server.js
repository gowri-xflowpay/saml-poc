const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { runServer } = require('saml-idp');

const CERT_PATH = path.join(__dirname, 'idp-public-cert.pem');
const KEY_PATH = path.join(__dirname, 'idp-private-key.pem');

const ACS_URL = 'http://localhost:5225/sso/acs';
const AUDIENCE = 'https://saml.boxyhq.com';
const ISSUER = 'urn:paypal:test:idp';
const PORT = 7001;

if (!fs.existsSync(CERT_PATH) || !fs.existsSync(KEY_PATH)) {
  console.log('Generating self-signed IdP certificate...');
  execSync(
    `openssl req -x509 -new -newkey rsa:2048 -nodes ` +
    `-subj '/C=US/ST=California/L=San Jose/O=PayPal/CN=PayPal Test IdP' ` +
    `-keyout "${KEY_PATH}" -out "${CERT_PATH}" -days 7300`,
    { stdio: 'inherit' }
  );
  console.log('Certificate generated.\n');
}

runServer({
  host: '0.0.0.0',
  port: PORT,
  cert: CERT_PATH,
  key: KEY_PATH,
  issuer: ISSUER,
  acsUrl: ACS_URL,
  audience: AUDIENCE,
  config: {
    metadata: [
      {
        id: 'email',
        optional: false,
        displayName: 'E-Mail Address',
        description: 'The e-mail address of the user',
        multiValue: false,
      },
      {
        id: 'firstName',
        optional: false,
        displayName: 'First Name',
        description: 'First name of the user',
        multiValue: false,
      },
      {
        id: 'lastName',
        optional: false,
        displayName: 'Last Name',
        description: 'Last name of the user',
        multiValue: false,
      },
      {
        id: 'displayName',
        optional: true,
        displayName: 'Display Name',
        description: 'Display name of the user',
        multiValue: false,
      },
    ],
    user: {
      userName: 'paypal.merchant@xflowpay.com',
      email: 'paypal.merchant@xflowpay.com',
      firstName: 'PayPal',
      lastName: 'Merchant',
      displayName: 'PayPal Merchant User',
    },
  },
});

console.log(`
================================================
  PayPal SAML IdP (Mock) Started
================================================
  Web UI:    http://localhost:${PORT}
  Metadata:  http://localhost:${PORT}/metadata
  SSO URL:   http://localhost:${PORT}/saml/sso
  ACS URL:   ${ACS_URL}
  Audience:  ${AUDIENCE}
  Issuer:    ${ISSUER}
================================================

  Default test user:
    Email:    paypal.merchant@xflowpay.com
    Name:     PayPal Merchant
================================================
`);
