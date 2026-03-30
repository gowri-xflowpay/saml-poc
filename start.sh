#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
  echo ""
  echo "Shutting down..."
  kill $IDP_PID $JACKSON_PID 2>/dev/null || true
  wait $IDP_PID $JACKSON_PID 2>/dev/null || true
  echo "Done."
}
trap cleanup EXIT INT TERM

echo "=================================="
echo "  PayPal SAML SSO — POC Startup"
echo "=================================="
echo ""

# Install dependencies
echo "[1/4] Installing PayPal SAML IdP dependencies..."
cd "$ROOT_DIR/paypal-saml-idp"
npm install --silent 2>&1 | tail -1
echo ""

echo "[2/4] Installing Jackson Bridge dependencies..."
cd "$ROOT_DIR/jackson-bridge"
npm install --silent 2>&1 | tail -1
echo ""

# Start PayPal SAML IdP
echo "[3/4] Starting PayPal SAML IdP (port 7001)..."
cd "$ROOT_DIR/paypal-saml-idp"
node server.js &
IDP_PID=$!
sleep 3

# Start Jackson Bridge
echo "[4/4] Starting Jackson Bridge + Demo App (port 5225)..."
cd "$ROOT_DIR/jackson-bridge"
node server.js &
JACKSON_PID=$!

echo ""
echo "Both servers starting. Open http://localhost:5225 when ready."
echo "Press Ctrl+C to stop all services."
echo ""

wait
