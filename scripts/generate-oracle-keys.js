#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

console.log('🔑 Generating oracle secret...');

// Check if oracle secret already exists in .env
const envPath = path.join(__dirname, '../app/.env.local');
let existingSecret = null;

if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  const match = envContent.match(/^ORACLE_SECRET_KEY=(.*)$/m);
  if (match) {
    existingSecret = match[1];
    console.log('📋 Using existing oracle secret from .env.local');
  }
}

// Generate new secret only if one doesn't exist
let oracleSecretHex, oracleSecretBigInt;
if (existingSecret) {
  oracleSecretHex = existingSecret;
  oracleSecretBigInt = BigInt(oracleSecretHex);
} else {
  // Generate a random secret (32 bytes = 256 bits for good security)
  const oracleSecret = crypto.randomBytes(32);
  oracleSecretHex = '0x' + oracleSecret.toString('hex');
  oracleSecretBigInt = BigInt(oracleSecretHex);
  console.log('✨ Generated new oracle secret');
}

console.log('Oracle Secret:', oracleSecretHex);

// Read the circuit template
const circuitPath = path.join(__dirname, '../circuits/token_ownership.circom');
let circuitContent = fs.readFileSync(circuitPath, 'utf8');

// Replace the placeholder OR existing oracle secret with new one
circuitContent = circuitContent.replace(
  /TokenOwnership\((?:ORACLE_SECRET|\d+)\)/,
  `TokenOwnership(${oracleSecretBigInt})`
);

// Write the updated circuit
fs.writeFileSync(circuitPath, circuitContent);

// Save the secret to .env file for the API (only if it's new)
if (!existingSecret) {
  let envContent = '';

  // Read existing .env if it exists
  if (fs.existsSync(envPath)) {
    envContent = fs.readFileSync(envPath, 'utf8');
  }

  // Update or add the oracle secret key
  const oracleKeyRegex = /^ORACLE_SECRET_KEY=.*$/m;
  const newOracleKey = `ORACLE_SECRET_KEY=${oracleSecretHex}`;

  if (oracleKeyRegex.test(envContent)) {
    envContent = envContent.replace(oracleKeyRegex, newOracleKey);
  } else {
    envContent += envContent.endsWith('\n') ? '' : '\n';
    envContent += newOracleKey + '\n';
  }

  fs.writeFileSync(envPath, envContent);
}

console.log('✅ Oracle secret generated and injected into circuit');
console.log('✅ Secret saved to app/.env.local');
console.log('⚠️  Keep the oracle secret private!');