# ZK Mint Template

A complete template for building privacy-preserving NFT minting using Zero-Knowledge proofs and Arbitrum Stylus.

## 🚀 Features

- **Privacy-First**: Prove token ownership without revealing exact balances
- **Zero-Knowledge Proofs**: Uses Groth16 for efficient verification
- **Arbitrum Stylus**: Rust-based smart contracts with EVM compatibility
- **thirdweb Integration**: Easy wallet connection and contract interaction
- **Full-Stack Template**: Complete setup with frontend, backend, and contracts

## 🏗 Architecture

```
stylus-zk-mint/
├── contracts/          # Arbitrum Stylus contracts (Rust)
├── circuits/           # ZK circuits for token ownership proof
├── app/               # Next.js frontend with API routes
└── setup.sh           # One-command setup script
```

## 🛠 Prerequisites

- [Node.js](https://nodejs.org/) (>= 20.18.0)
- [pnpm](https://pnpm.io/) package manager
- [Rust](https://rustup.rs/) with cargo
- [circom](https://docs.circom.io/getting-started/installation/) for ZK circuits
- [Stylus CLI](https://docs.arbitrum.io/stylus/stylus-quickstart) for contract deployment

## 🚀 Quick Start

1. **Clone the template**:

   ```bash
   git clone git@github.com:thirdweb-example/stylus-zk-mint.git
   cd stylus-zk-mint
   ```

2. **Run setup script**:

   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Deploy the contract**:

   ```bash
   cd contracts
   npx thirdweb@latest deploy-stylus -k <THIRDWEB SECRET KEY>
   # Copy the deployed contract address
   ```

   Arkworks address: 0x2e9e7b36619fed922da9e54ccb0873d4a0bc6594 (Arbitrum Sepolia)

4. **Update app configuration**:

   ```bash
   cd ../app
   # Edit pages/index.tsx and update ZK_MINT_CONTRACT_ADDRESS
   ```

5. **Start the app**:
   ```bash
   pnpm dev
   # Visit http://localhost:3000
   ```

## 📋 How It Works

### For Users (NFT Minters)

1. Connect wallet to the dApp
2. Enter a token contract address and minimum balance
3. Generate ZK proof (proves you own ≥ X tokens without revealing exact amount)
4. Mint NFT using the proof

### Technical Flow

1. **Frontend** calls API route with user's wallet address and token requirements
2. **API route** checks actual on-chain token balance via RPC
3. **ZK Circuit** generates proof that `actual_balance >= required_balance`
4. **Smart Contract** verifies the proof and mints NFT

## 🔒 Privacy Benefits

- **Balance Privacy**: Your exact token balance is never revealed
- **Identity Privacy**: Proves membership without revealing which member
- **Replay Protection**: Each proof includes a unique nullifier

## 🛠 Development

### Testing the Contract

```bash
cd contracts
cargo test
```

### Building Circuits

```bash
cd circuits
pnpm run build
```

### Running the App

```bash
cd app
pnpm dev
```

## 🚀 Deployment

### Contract Deployment

```bash
cd contracts
cargo stylus deploy --endpoint arbitrum-sepolia
```

### App Deployment (Vercel)

```bash
cd app
vercel deploy
```

## 🔧 Configuration

### Environment Variables

Create `app/.env.local`:

```bash
RPC_URL=https://sepolia-rollup.arbitrum.io/rpc
SUPPORTED_TOKENS=0x...,0x...  # Optional: restrict to specific tokens
```

### Customization

- **Token Requirements**: Modify the circuit in `circuits/token_ownership.circom`
- **UI Styling**: Update `app/styles/Home.module.css`
- **Contract Logic**: Modify `contracts/src/lib.rs`

## 📚 Learn More

- [Arbitrum Stylus Documentation](https://docs.arbitrum.io/stylus/)
- [thirdweb Documentation](https://portal.thirdweb.com/)
- [Circom Documentation](https://docs.circom.io/)
- [ZK-SNARKs Explained](https://blog.ethereum.org/2016/12/05/zksnarks-in-a-nutshell)

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## ⚠️ Security Notice

This is a template for educational and development purposes. Before deploying to production:

1. Audit your ZK circuit thoroughly
2. Test with various edge cases
3. Consider formal verification of your contracts
4. Review all cryptographic implementations
