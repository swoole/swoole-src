#!/bin/bash

# Generate self-signed SSL certificate for HTTP/3 testing
# This script creates a certificate valid for 365 days

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="${SCRIPT_DIR}/ssl"

mkdir -p "$SSL_DIR"
cd "$SSL_DIR"

echo "Generating self-signed SSL certificate..."

# Generate private key
openssl genrsa -out key.pem 2048 2>/dev/null

# Generate certificate
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null

echo "SSL certificate generated:"
echo "  Certificate: $SSL_DIR/cert.pem"
echo "  Private Key: $SSL_DIR/key.pem"
echo ""
echo "Note: This is a self-signed certificate for testing only."
echo "For production use, obtain a valid certificate from a trusted CA."
