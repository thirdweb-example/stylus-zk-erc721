#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

console.log('🔑 Generating oracle secret...');

// Generate a random secret (32 bytes = 256 bits for good security)
const oracleSecret = crypto.randomBytes(32);
const oracleSecretHex = '0x' + oracleSecret.toString('hex');
const oracleSecretBigInt = BigInt(oracleSecretHex);

console.log('Oracle Secret:', oracleSecretHex);

// Read the circuit template
const circuitPath = path.join(__dirname, '../circuits/token_ownership.circom');
let circuitContent = fs.readFileSync(circuitPath, 'utf8');

// Replace the placeholder with actual oracle secret
circuitContent = circuitContent.replace(
  'TokenOwnership(ORACLE_SECRET)',
  `TokenOwnership(${oracleSecretBigInt})`
);

// Write the updated circuit
fs.writeFileSync(circuitPath, circuitContent);

// Save the secret to .env file for the API
const envPath = path.join(__dirname, '../app/.env.local');
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

console.log('✅ Oracle secret generated and injected into circuit');
console.log('✅ Secret saved to app/.env.local');
console.log('⚠️  Keep the oracle secret private!');