pragma circom 2.0.0;

include "comparators.circom";
include "poseidon.circom";

// Circuit: Prove token ownership with oracle commitment verification
// Oracle secret is HARDCODED during circuit compilation for security
template TokenOwnership(oracle_secret) {
    // Private inputs
    signal input actual_balance;        // Private: actual token balance from oracle
    signal input salt;                  // Private: randomness for uniqueness
    
    // Public inputs
    signal input min_required_balance;  // Public: minimum balance threshold
    signal input token_contract_hash;   // Public: hash of token contract
    signal input user_address_hash;     // Public: hash of user address
    signal input timestamp;             // Public: when oracle signed the data
    signal input oracle_commitment;    // Public: oracle's commitment to the balance data
    
    // Outputs (automatically public)
    signal output nullifier;  // Prevents double-use of same proof
    
    // 1. Verify oracle commitment 
    // Expected commitment = poseidon(oracle_secret, actual_balance, token_contract_hash, user_address_hash, timestamp)
    component commitmentCheck = Poseidon(5);
    commitmentCheck.inputs[0] <== oracle_secret;  // Hardcoded secret
    commitmentCheck.inputs[1] <== actual_balance;
    commitmentCheck.inputs[2] <== token_contract_hash;
    commitmentCheck.inputs[3] <== user_address_hash;
    commitmentCheck.inputs[4] <== timestamp;
    
    // Oracle commitment must match expected value
    oracle_commitment === commitmentCheck.out;
    
    // 2. Check that actual_balance >= min_required_balance  
    component gte = GreaterEqThan(64);
    gte.in[0] <== actual_balance;
    gte.in[1] <== min_required_balance;
    
    // 3. Ensure the balance check passes
    gte.out === 1;
    
    // 4. Generate unique nullifier to prevent proof reuse
    component nullifierHash = Poseidon(5);
    nullifierHash.inputs[0] <== actual_balance;
    nullifierHash.inputs[1] <== salt;
    nullifierHash.inputs[2] <== token_contract_hash;
    nullifierHash.inputs[3] <== user_address_hash;
    nullifierHash.inputs[4] <== timestamp;
    
    // Output the nullifier
    nullifier <== nullifierHash.out;
}

// Main component: Oracle secret gets injected here during setup
component main {public [min_required_balance, token_contract_hash, user_address_hash, timestamp, oracle_commitment]} = TokenOwnership(ORACLE_SECRET);