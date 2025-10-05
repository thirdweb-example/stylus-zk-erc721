import { ConnectWallet, useAddress, useContract, useContractWrite } from "@thirdweb-dev/react";
import styles from "../styles/Home.module.css";
import { NextPage } from "next";
import { useState } from "react";
import { ethers } from "ethers";

const Home: NextPage = () => {
  const address = useAddress();
  const [tokenContract, setTokenContract] = useState("");
  const [minBalance, setMinBalance] = useState("");
  const [isGeneratingProof, setIsGeneratingProof] = useState(false);
  const [proofResult, setProofResult] = useState<any>(null);
  const [error, setError] = useState("");

  // Replace with your deployed contract address
  const ZK_MINT_CONTRACT_ADDRESS = "0x..."; // TODO: Update after contract deployment

  const { contract } = useContract(ZK_MINT_CONTRACT_ADDRESS);
  const { mutateAsync: mintWithProof } = useContractWrite(contract, "mint_with_zk_proof");

  const generateProof = async () => {
    if (!address || !tokenContract || !minBalance) {
      setError("Please connect wallet and fill all fields");
      return;
    }

    setIsGeneratingProof(true);
    setError("");
    setProofResult(null);

    try {
      const response = await fetch('/api/generate-proof', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userAddress: address,
          tokenContract,
          minRequiredBalance: parseFloat(minBalance),
          salt: Math.floor(Math.random() * 1000000)
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to generate proof');
      }

      setProofResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsGeneratingProof(false);
    }
  };

  const mintNFT = async () => {
    if (!proofResult || !address) return;

    try {
      setError("");
      
      // Format proof data for Stylus contract
      const proofData = new Uint8Array(256); // 256 bytes for Groth16 proof
      // TODO: Convert proofResult.proof to bytes format expected by Stylus
      
      const publicInputs = proofResult.publicSignals.map((signal: string) => 
        ethers.BigNumber.from(signal)
      );

      await mintWithProof({
        args: [address, proofData, publicInputs]
      });

      alert("NFT minted successfully!");
      setProofResult(null);
    } catch (err: any) {
      setError(err.message || "Failed to mint NFT");
    }
  };

  return (
    <main className={styles.main}>
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>
            <span className={styles.gradientText0}>ZK Mint</span>
          </h1>

          <p className={styles.description}>
            Mint NFTs by proving token ownership without revealing your balance
          </p>

          <div className={styles.connect}>
            <ConnectWallet />
          </div>
        </div>

        {address && (
          <div className={styles.mintSection}>
            <div className={styles.card}>
              <h2>Prove Token Ownership & Mint</h2>
              
              <div className={styles.inputGroup}>
                <label>Token Contract Address:</label>
                <input
                  type="text"
                  placeholder="0x..."
                  value={tokenContract}
                  onChange={(e) => setTokenContract(e.target.value)}
                  className={styles.input}
                />
              </div>

              <div className={styles.inputGroup}>
                <label>Minimum Balance Required:</label>
                <input
                  type="number"
                  placeholder="100"
                  value={minBalance}
                  onChange={(e) => setMinBalance(e.target.value)}
                  className={styles.input}
                />
              </div>

              <button
                onClick={generateProof}
                disabled={isGeneratingProof || !address || !tokenContract || !minBalance}
                className={styles.button}
              >
                {isGeneratingProof ? "Generating Proof..." : "Generate ZK Proof"}
              </button>

              {error && <div className={styles.error}>{error}</div>}

              {proofResult && (
                <div className={styles.proofResult}>
                  <h3>✅ Proof Generated!</h3>
                  <p>Token: {proofResult.metadata.tokenSymbol}</p>
                  <p>Your Balance: {proofResult.metadata.userBalance}</p>
                  <p>Required: {proofResult.metadata.requiredBalance}</p>
                  
                  <button
                    onClick={mintNFT}
                    className={styles.button}
                  >
                    Mint NFT with Proof
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </main>
  );
};

export default Home;
