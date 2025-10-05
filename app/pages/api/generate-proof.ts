import type { NextApiRequest, NextApiResponse } from 'next';
import { ethers } from 'ethers';
import snarkjs from 'snarkjs';
import path from 'path';
import fs from 'fs';
import { poseidon1, poseidon5 } from 'poseidon-lite';

// API route for generating ZK proofs for token ownership
export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { 
      userAddress, 
      tokenContract, 
      minRequiredBalance,
      salt 
    } = req.body;

    // Validate inputs
    if (!ethers.utils.isAddress(userAddress) || !ethers.utils.isAddress(tokenContract)) {
      return res.status(400).json({ error: 'Invalid address format' });
    }

    // Validate oracle secret key
    const oracleSecretHex = process.env.ORACLE_SECRET_KEY;
    if (!oracleSecretHex) {
      return res.status(500).json({ error: 'Oracle secret key not configured' });
    }
    const oracleSecret = BigInt(oracleSecretHex);

    // Circuit file paths (copied by setup script)
    const wasmPath = path.join(process.cwd(), 'lib/circuits/token_ownership.wasm');
    const zkeyPath = path.join(process.cwd(), 'lib/circuits/circuit_final.zkey');

    // Check if circuit files exist
    if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
      return res.status(500).json({ 
        error: 'Circuit files not found. Please run circuit setup first.',
        missing: {
          wasm: !fs.existsSync(wasmPath),
          zkey: !fs.existsSync(zkeyPath)
        }
      });
    }

    // RPC provider for Arbitrum Sepolia
    const provider = new ethers.providers.JsonRpcProvider(
      process.env.RPC_URL || 'https://sepolia-rollup.arbitrum.io/rpc'
    );

    // ERC20 ABI for balance checking
    const ERC20_ABI = [
      'function balanceOf(address owner) view returns (uint256)',
      'function decimals() view returns (uint8)',
      'function symbol() view returns (string)',
      'function name() view returns (string)'
    ];

    // 1. Check actual token balance on-chain
    const tokenContractInstance = new ethers.Contract(tokenContract, ERC20_ABI, provider);
    const [actualBalance, decimals, symbol] = await Promise.all([
      tokenContractInstance.balanceOf(userAddress),
      tokenContractInstance.decimals(),
      tokenContractInstance.symbol()
    ]);
    
    // Convert balance to readable format
    const balanceFormatted = Number(ethers.utils.formatUnits(actualBalance, decimals));
    
    console.log(`User ${userAddress} has ${balanceFormatted} ${symbol} tokens`);
    
    // 2. Check if user has enough tokens
    if (balanceFormatted < minRequiredBalance) {
      return res.status(400).json({ 
        error: 'Insufficient token balance',
        required: minRequiredBalance,
        actual: balanceFormatted,
        token: symbol
      });
    }

    // 3. Generate oracle commitment for balance data
    const timestamp = Math.floor(Date.now() / 1000);
    const actualBalanceScaled = Math.floor(balanceFormatted * (10 ** 6)); // Scale to avoid decimals
    const tokenContractHash = BigInt(ethers.utils.keccak256(ethers.utils.toUtf8Bytes(tokenContract))) % (2n ** 254n);
    const userAddressHash = BigInt(ethers.utils.keccak256(ethers.utils.toUtf8Bytes(userAddress))) % (2n ** 254n);
    
    // Generate oracle commitment: poseidon(oracle_secret, actual_balance, token_contract_hash, user_address_hash, timestamp)
    const oracleCommitment = poseidon5([
      oracleSecret,
      BigInt(actualBalanceScaled),
      tokenContractHash,
      userAddressHash,
      BigInt(timestamp)
    ]);

    // 4. Prepare circuit inputs (must match circuit template exactly)
    const saltValue = salt || Math.floor(Math.random() * 1000000);
    const inputs = {
      // Private inputs
      actual_balance: actualBalanceScaled,
      salt: saltValue,
      
      // Public inputs (oracle secret is hardcoded in circuit)
      min_required_balance: Math.floor(minRequiredBalance * (10 ** 6)),
      token_contract_hash: tokenContractHash.toString(),
      user_address_hash: userAddressHash.toString(),
      timestamp: timestamp,
      oracle_commitment: oracleCommitment.toString()
    };

    // 5. Generate ZK proof
    console.log('Generating proof...');
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      wasmPath,
      zkeyPath
    );

    // 6. Format proof for Stylus contract (256 bytes total)
    const proofBytes = Buffer.concat([
      // G1 point A (64 bytes: 32 + 32)
      Buffer.from(ethers.utils.hexZeroPad(proof.pi_a[0], 32).slice(2), 'hex'),
      Buffer.from(ethers.utils.hexZeroPad(proof.pi_a[1], 32).slice(2), 'hex'),
      
      // G2 point B (128 bytes: 32 + 32 + 32 + 32) 
      Buffer.from(ethers.utils.hexZeroPad(proof.pi_b[0][1], 32).slice(2), 'hex'),
      Buffer.from(ethers.utils.hexZeroPad(proof.pi_b[0][0], 32).slice(2), 'hex'),
      Buffer.from(ethers.utils.hexZeroPad(proof.pi_b[1][1], 32).slice(2), 'hex'),
      Buffer.from(ethers.utils.hexZeroPad(proof.pi_b[1][0], 32).slice(2), 'hex'),
      
      // G1 point C (64 bytes: 32 + 32)
      Buffer.from(ethers.utils.hexZeroPad(proof.pi_c[0], 32).slice(2), 'hex'),
      Buffer.from(ethers.utils.hexZeroPad(proof.pi_c[1], 32).slice(2), 'hex'),
    ]);

    res.json({
      success: true,
      proof: '0x' + proofBytes.toString('hex'),
      publicSignals: publicSignals.map((signal: string) => ethers.BigNumber.from(signal).toString()),
      metadata: {
        userBalance: balanceFormatted,
        requiredBalance: minRequiredBalance,
        tokenContract,
        tokenSymbol: symbol,
        userAddress,
        oracleCommitment: oracleCommitment.toString(),
        timestamp,
        network: 'arbitrum-sepolia'
      }
    });

  } catch (error) {
    console.error('Proof generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate proof',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}