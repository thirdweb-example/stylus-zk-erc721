extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::{Address, U256};
use stylus_sdk::{
    prelude::*,
    call::RawCall,
};

mod verifying_key;
use verifying_key::get_verifying_key;

type G1Point = [u8; 64];   // 32 bytes x + 32 bytes y
type G2Point = [u8; 128];  // 32 bytes x0 + 32 bytes x1 + 32 bytes y0 + 32 bytes y1
type Scalar = [u8; 32];    // 32 bytes for field element

//============================================================================
// PRECOMPILE BACKEND FOR BN254 OPERATIONS (Renegade style)
//============================================================================

const EC_ADD_PRECOMPILE: u8 = 0x06;
const EC_MUL_PRECOMPILE: u8 = 0x07;
const EC_PAIRING_PRECOMPILE: u8 = 0x08;

/// The BN254 arithmetic backend that calls EVM precompiles
pub struct PrecompileBackend;

impl PrecompileBackend {
    /// Call ecAdd using EVM precompile for G1 point addition
    pub fn ec_add(host: &dyn stylus_sdk::prelude::Host, a: &G1Point, b: &G1Point) -> Result<G1Point, Vec<u8>> {
        if Self::is_g1_zero(a) {
            return Ok(*b);
        }
        if Self::is_g1_zero(b) {
            return Ok(*a);
        }
        
        // Prepare calldata for precompile (128 bytes: 64 + 64)
        let mut calldata = [0u8; 128];
        calldata[0..64].copy_from_slice(a);
        calldata[64..128].copy_from_slice(b);
        
        // Call EVM precompile directly
        let result = unsafe {
            RawCall::new(host).call(Address::with_last_byte(EC_ADD_PRECOMPILE), &calldata)
        }.map_err(|_| "ecAdd precompile failed".as_bytes().to_vec())?;
        
        // Return result as G1Point
        if result.len() != 64 {
            return Err("Invalid ecAdd result length".as_bytes().to_vec());
        }
        let mut point = [0u8; 64];
        point.copy_from_slice(&result);
        Ok(point)
    }
    
    /// Call ecMul using EVM precompile for G1 scalar multiplication
    pub fn ec_mul(host: &dyn stylus_sdk::prelude::Host, scalar: &Scalar, point: &G1Point) -> Result<G1Point, Vec<u8>> {
        if Self::is_scalar_zero(scalar) || Self::is_g1_zero(point) {
            return Ok([0u8; 64]); // Zero point
        }
        
        // Prepare calldata for precompile (96 bytes: 64 + 32)
        let mut calldata = [0u8; 96];
        calldata[0..64].copy_from_slice(point);
        calldata[64..96].copy_from_slice(scalar);
        
        // Call EVM precompile directly
        let result = unsafe {
            RawCall::new(host).call(Address::with_last_byte(EC_MUL_PRECOMPILE), &calldata)
        }.map_err(|_| "ecMul precompile failed".as_bytes().to_vec())?;
        
        // Return result as G1Point
        if result.len() != 64 {
            return Err("Invalid ecMul result length".as_bytes().to_vec());
        }
        let mut point = [0u8; 64];
        point.copy_from_slice(&result);
        Ok(point)
    }
    
    
    /// Check if G1 point is zero (point at infinity)
    fn is_g1_zero(point: &G1Point) -> bool {
        point.iter().all(|&b| b == 0)
    }
    
    /// Check if scalar is zero
    fn is_scalar_zero(scalar: &Scalar) -> bool {
        scalar.iter().all(|&b| b == 0)
    }
    
    /// Negate a G1 point by negating the y coordinate (mod p)
    fn negate_g1_point(point: &G1Point) -> G1Point {
        if Self::is_g1_zero(point) {
            return *point; // Zero point negation is zero
        }
        
        let mut negated = *point;
        // For BN254, p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
        // EVM uses big-endian format, so p in big-endian bytes:
        let p_bytes = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47
        ];
        
        // Extract y coordinate (bytes 32-63) and compute p - y
        let mut y_bytes = [0u8; 32];
        y_bytes.copy_from_slice(&point[32..64]);
        
        // Perform p - y using big integer arithmetic (big-endian)
        let mut borrow = 0u64;
        for i in (0..32).rev() {
            let p_val = p_bytes[i] as u64 - borrow;
            let y_val = y_bytes[i] as u64;
            
            if p_val >= y_val {
                negated[32 + i] = (p_val - y_val) as u8;
                borrow = 0;
            } else {
                negated[32 + i] = (256 + p_val - y_val) as u8;
                borrow = 1;
            }
        }
        
        negated
    }
}


#[derive(Debug, Clone)]
pub struct ZKProof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub alpha_g1: G1Point,
    pub beta_g2: G2Point,
    pub gamma_g2: G2Point,
    pub delta_g2: G2Point,
    pub gamma_abc_g1: Vec<G1Point>,
}

impl ZKProof {
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 256 {
            return Err("Invalid proof length");
        }
        
        // Parse G1 point A (64 bytes)
        let mut a = [0u8; 64];
        a.copy_from_slice(&data[0..64]);
        
        // Parse G2 point B (128 bytes)
        let mut b = [0u8; 128];
        b.copy_from_slice(&data[64..192]);
        
        // Parse G1 point C (64 bytes)
        let mut c = [0u8; 64];
        c.copy_from_slice(&data[192..256]);
        
        Ok(ZKProof { a, b, c })
    }
}

impl VerifyingKey {
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        // Expected format: alpha_g1 (64) + beta_g2 (128) + gamma_g2 (128) + delta_g2 (128) + 
        // gamma_abc_length (4) + gamma_abc_points (64 * length)
        if data.len() < 452 { // 64 + 128 + 128 + 128 + 4 = 452 minimum
            return Err("Invalid verifying key length");
        }
        
        let mut offset = 0;
        
        // Parse alpha G1 (64 bytes)
        let mut alpha_g1 = [0u8; 64];
        alpha_g1.copy_from_slice(&data[offset..offset + 64]);
        offset += 64;
        
        // Parse beta G2 (128 bytes)
        let mut beta_g2 = [0u8; 128];
        beta_g2.copy_from_slice(&data[offset..offset + 128]);
        offset += 128;
        
        // Parse gamma G2 (128 bytes)
        let mut gamma_g2 = [0u8; 128];
        gamma_g2.copy_from_slice(&data[offset..offset + 128]);
        offset += 128;
        
        // Parse delta G2 (128 bytes)
        let mut delta_g2 = [0u8; 128];
        delta_g2.copy_from_slice(&data[offset..offset + 128]);
        offset += 128;
        
        // Parse gamma ABC length (4 bytes)
        if data.len() < offset + 4 {
            return Err("Invalid gamma ABC length");
        }
        let gamma_abc_len = u32::from_be_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;
        
        // Parse gamma ABC G1 points
        if data.len() < offset + (gamma_abc_len * 64) {
            return Err("Invalid gamma ABC points length");
        }
        
        let mut gamma_abc_g1 = Vec::with_capacity(gamma_abc_len);
        for _ in 0..gamma_abc_len {
            let mut point = [0u8; 64];
            point.copy_from_slice(&data[offset..offset + 64]);
            gamma_abc_g1.push(point);
            offset += 64;
        }
        
        Ok(VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        })
    }

}

//============================================================================
// UNIFIED ZK MINT CONTRACT
//============================================================================

sol_storage! {
    #[entrypoint]
    pub struct ZKMintContract {
        address owner;
        uint256 next_token_id;
        mapping(uint256 => address) token_owners;
        mapping(address => uint256) token_balances;
        mapping(uint256 => address) token_approvals;
        mapping(address => mapping(address => bool)) operator_approvals;
        
        // Nullifier tracking to prevent replay attacks
        mapping(uint256 => bool) used_nullifiers;
    }
}

#[public]
impl ZKMintContract {
    #[constructor]
    pub fn constructor(&mut self, owner: Address) -> Result<(), Vec<u8>> {
        self.owner.set(owner);
        self.next_token_id.set(U256::from(1));

        Ok(())
    }


    // ========================================================================
    // ZK PROOF VERIFICATION  
    // ========================================================================

    pub fn verify_proof(
        &self,
        proof_data: Vec<u8>,
        public_inputs: Vec<U256>,
    ) -> Result<bool, Vec<u8>> {
        // Parse the ZK proof
        let proof = ZKProof::deserialize(&proof_data)?;
        
        // Convert U256 public inputs to Scalar (raw bytes)
        let mut scalar_inputs = Vec::new();
        for input in public_inputs.iter() {
            let bytes: [u8; 32] = input.to_be_bytes();
            scalar_inputs.push(bytes);
        }
        
        // Use compile-time constants instead of storage reads (gas optimization)
        let vk = get_verifying_key();
        
        // Perform verification
        self.groth16_verify(&proof, &vk, &scalar_inputs)
    }

    // ========================================================================
    // NFT MINTING
    // ========================================================================

    pub fn mint_with_zk_proof(
        &mut self,
        to: Address,
        proof_data: Vec<u8>,
        public_inputs: Vec<U256>,
    ) -> Result<U256, Vec<u8>> {
        // Check we have the expected number of public inputs (nullifier + 5 inputs)
        if public_inputs.len() != 6 {
            return Err("Invalid number of public inputs".into());
        }
        
        // Extract nullifier (first element - circuit output in snarkjs ordering)
        let nullifier = public_inputs[0];
        
        // Check if nullifier has been used before (prevent replay attacks)
        if self.used_nullifiers.get(nullifier) {
            return Err("Nullifier already used - proof replay detected".into());
        }
        
        // Verify the ZK proof (pass all public signals to groth16_verify)
        if !self.verify_proof(proof_data, public_inputs)? {
            return Err("Invalid ZK proof".into());
        }
        
        // Mark nullifier as used to prevent future replay
        self.used_nullifiers.setter(nullifier).set(true);

        // Mint the NFT
        let token_id = self.next_token_id.get();
        self.token_owners.setter(token_id).set(to);
        
        let current_balance = self.token_balances.getter(to).get();
        self.token_balances.setter(to).set(current_balance + U256::from(1));
        
        self.next_token_id.set(token_id + U256::from(1));
        
        Ok(token_id)
    }

    // ========================================================================
    // ERC721 VIEW FUNCTIONS
    // ========================================================================

    pub fn balance_of(&self, owner: Address) -> U256 {
        self.token_balances.getter(owner).get()
    }

    pub fn owner_of(&self, token_id: U256) -> Result<Address, Vec<u8>> {
        let owner = self.token_owners.getter(token_id).get();
        if owner == Address::ZERO {
            return Err("Token does not exist".into());
        }
        Ok(owner)
    }

    pub fn get_next_token_id(&self) -> U256 {
        self.next_token_id.get()
    }
}

impl ZKMintContract {

    fn groth16_verify(
        &self,
        proof: &ZKProof,
        vk: &VerifyingKey,
        public_inputs: &[Scalar],
    ) -> Result<bool, Vec<u8>> {
        if public_inputs.len() + 1 != vk.gamma_abc_g1.len() {
            return Err("Wrong number of public inputs".into());
        }

        // Compute vk_x = gamma_abc_g1[0] + sum(public_inputs[i] * gamma_abc_g1[i+1])
        // snarkjs returns public signals as: [nullifier, min_required_balance, token_contract_hash, user_address_hash, timestamp, oracle_commitment]
        // gamma_abc_g1 has: [constant, nullifier_coeff, min_req_coeff, token_coeff, user_coeff, timestamp_coeff, oracle_coeff]
        let mut vk_x = vk.gamma_abc_g1[0];
        
        // Multiply each public input by its corresponding gamma_abc coefficient and add to vk_x
        for (i, input) in public_inputs.iter().enumerate() {
            if i + 1 < vk.gamma_abc_g1.len() {
                let gamma_abc_term = PrecompileBackend::ec_mul(&*self.vm(), input, &vk.gamma_abc_g1[i + 1])?;
                vk_x = PrecompileBackend::ec_add(&*self.vm(), &vk_x, &gamma_abc_term)?;
            }
        }

        // Negate some points for the pairing check
        let neg_alpha = PrecompileBackend::negate_g1_point(&vk.alpha_g1);
        let neg_vk_x = PrecompileBackend::negate_g1_point(&vk_x);
        let neg_c = PrecompileBackend::negate_g1_point(&proof.c);

        // Perform single 4-way pairing check for Groth16
        // Verify: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1
        let mut calldata = [0u8; 768]; // 4 pairs * 192 bytes each
        
        // Serialize all 4 pairs for the pairing precompile
        calldata[0..64].copy_from_slice(&proof.a);
        calldata[64..192].copy_from_slice(&proof.b);
        calldata[192..256].copy_from_slice(&neg_alpha);
        calldata[256..384].copy_from_slice(&vk.beta_g2);
        calldata[384..448].copy_from_slice(&neg_vk_x);
        calldata[448..576].copy_from_slice(&vk.gamma_g2);
        calldata[576..640].copy_from_slice(&neg_c);
        calldata[640..768].copy_from_slice(&vk.delta_g2);
        
        // Call EVM pairing precompile with all 4 pairs
        let result = unsafe {
            RawCall::new(self.vm())
                .call(Address::with_last_byte(EC_PAIRING_PRECOMPILE), &calldata)
        }.map_err(|_| b"Pairing precompile failed".to_vec())?;
        
        // Result is 32 bytes, return true if last byte is 1
        Ok(result.len() == 32 && result[31] == 1)
    }
}