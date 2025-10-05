extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::{Address, U256};
use alloy_sol_types::sol;
use stylus_sdk::{
    prelude::*,
    call::RawCall,
};

#[cfg(any(feature = "verifier", feature = "vkeys"))]
use ark_bn254::{Fq, Fr, G1Affine, G2Affine, Fq2};
#[cfg(any(feature = "verifier", feature = "vkeys"))]
use ark_ec::AffineRepr;
#[cfg(any(feature = "verifier", feature = "vkeys"))]
use ark_ff::{PrimeField, Zero, BigInteger};


sol_interface! {
    interface IZKVerifier {
        function verify_proof(bytes calldata proof_data, uint256[] calldata public_inputs) external view returns (bool);
    }
}

sol_interface! {
    interface IZKVKeys {
        function get_verifying_key() external view returns (bytes memory);
        function is_key_initialized() external view returns (bool);
    }
}

//============================================================================
// PRECOMPILE BACKEND FOR BN254 OPERATIONS (Renegade style)
//============================================================================

#[cfg(any(feature = "verifier", feature = "vkeys"))]
const EC_ADD_PRECOMPILE: u8 = 0x06;
#[cfg(any(feature = "verifier", feature = "vkeys"))]
const EC_MUL_PRECOMPILE: u8 = 0x07;
#[cfg(any(feature = "verifier", feature = "vkeys"))]
const EC_PAIRING_PRECOMPILE: u8 = 0x08;

/// The BN254 arithmetic backend that calls EVM precompiles
#[cfg(any(feature = "verifier", feature = "vkeys"))]
pub struct PrecompileBackend;

#[cfg(any(feature = "verifier", feature = "vkeys"))]
impl PrecompileBackend {
    /// Call ecAdd precompile for G1 point addition
    pub fn ec_add(host: &dyn stylus_sdk::prelude::Host, a: G1Affine, b: G1Affine) -> Result<G1Affine, Vec<u8>> {
        if a.is_zero() {
            return Ok(b);
        }
        if b.is_zero() {
            return Ok(a);
        }
        
        // Serialize points for precompile (64 bytes each)
        let mut calldata = [0u8; 128];
        Self::serialize_g1_point(&a, &mut calldata[0..64]);
        Self::serialize_g1_point(&b, &mut calldata[64..128]);
        
        // Call ecAdd precompile
        let result = unsafe {
            RawCall::new(host)
                .call(Address::with_last_byte(EC_ADD_PRECOMPILE), &calldata)
                .map_err(|_| "ecAdd precompile failed".as_bytes().to_vec())?
        };
        
        // Deserialize result
        Self::deserialize_g1_point(&result)
    }
    
    /// Call ecMul precompile for G1 scalar multiplication
    pub fn ec_mul(host: &dyn stylus_sdk::prelude::Host, scalar: Fr, point: G1Affine) -> Result<G1Affine, Vec<u8>> {
        if scalar.is_zero() {
            return Ok(G1Affine::zero());
        }
        if point.is_zero() {
            return Ok(G1Affine::zero());
        }
        
        // Serialize point and scalar for precompile (96 bytes total)
        let mut calldata = [0u8; 96];
        Self::serialize_g1_point(&point, &mut calldata[0..64]);
        Self::serialize_scalar(&scalar, &mut calldata[64..96]);
        
        // Call ecMul precompile
        let result = unsafe {
            RawCall::new(host)
                .call(Address::with_last_byte(EC_MUL_PRECOMPILE), &calldata)
                .map_err(|_| "ecMul precompile failed".as_bytes().to_vec())?
        };
        
        // Deserialize result
        Self::deserialize_g1_point(&result)
    }
    
    /// Call ecPairing precompile for pairing check
    pub fn ec_pairing_check(
        host: &dyn stylus_sdk::prelude::Host,
        a1: G1Affine, b1: G2Affine,
        a2: G1Affine, b2: G2Affine,
    ) -> Result<bool, Vec<u8>> {
        // Serialize points for precompile (384 bytes total)
        let mut calldata = [0u8; 384];
        Self::serialize_g1_point(&a1, &mut calldata[0..64]);
        Self::serialize_g2_point(&b1, &mut calldata[64..192]);
        Self::serialize_g1_point(&a2, &mut calldata[192..256]);
        Self::serialize_g2_point(&b2, &mut calldata[256..384]);
        
        // Call ecPairing precompile
        let result = unsafe {
            RawCall::new(host)
                .call(Address::with_last_byte(EC_PAIRING_PRECOMPILE), &calldata)
                .map_err(|_| "ecPairing precompile failed".as_bytes().to_vec())?
        };
        
        // Result is 32 bytes, but we only care about the last byte
        Ok(result.len() == 32 && result[31] == 1)
    }
    
    /// Serialize G1 point to 64 bytes (32 bytes x, 32 bytes y)
    fn serialize_g1_point(point: &G1Affine, buffer: &mut [u8]) {
        use ark_ff::{BigInteger, PrimeField};
        let x_bytes = point.x.into_bigint().to_bytes_be();
        let y_bytes = point.y.into_bigint().to_bytes_be();
        buffer[0..32].copy_from_slice(&x_bytes);
        buffer[32..64].copy_from_slice(&y_bytes);
    }
    
    /// Serialize G2 point to 128 bytes (32 bytes each for x0, x1, y0, y1)
    fn serialize_g2_point(point: &G2Affine, buffer: &mut [u8]) {
        use ark_ff::{BigInteger, PrimeField};
        let x0_bytes = point.x.c0.into_bigint().to_bytes_be();
        let x1_bytes = point.x.c1.into_bigint().to_bytes_be();
        let y0_bytes = point.y.c0.into_bigint().to_bytes_be();
        let y1_bytes = point.y.c1.into_bigint().to_bytes_be();
        buffer[0..32].copy_from_slice(&x0_bytes);
        buffer[32..64].copy_from_slice(&x1_bytes);
        buffer[64..96].copy_from_slice(&y0_bytes);
        buffer[96..128].copy_from_slice(&y1_bytes);
    }
    
    /// Serialize scalar to 32 bytes
    fn serialize_scalar(scalar: &Fr, buffer: &mut [u8]) {
        use ark_ff::{BigInteger, PrimeField};
        let scalar_bytes = scalar.into_bigint().to_bytes_be();
        buffer.copy_from_slice(&scalar_bytes);
    }
    
    /// Deserialize G1 point from 64 bytes
    fn deserialize_g1_point(data: &[u8]) -> Result<G1Affine, Vec<u8>> {
        if data.len() != 64 {
            return Err("Invalid G1 point length".as_bytes().to_vec());
        }
        
        let x = Fq::from_be_bytes_mod_order(&data[0..32]);
        let y = Fq::from_be_bytes_mod_order(&data[32..64]);
        
        Ok(G1Affine::new(x, y))
    }
}


#[cfg(any(feature = "verifier", feature = "vkeys"))]
#[derive(Debug, Clone)]
pub struct ZKProof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

#[cfg(any(feature = "verifier", feature = "vkeys"))]
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub gamma_abc_g1: Vec<G1Affine>,
}

#[cfg(any(feature = "verifier", feature = "vkeys"))]
impl ZKProof {
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 256 {
            return Err("Invalid proof length");
        }
        
        // Parse G1 point A (64 bytes)
        let a_x = Fq::from_be_bytes_mod_order(&data[0..32]);
        let a_y = Fq::from_be_bytes_mod_order(&data[32..64]);
        let a = G1Affine::new_unchecked(a_x, a_y);
        
        // Parse G2 point B (128 bytes)
        let b_x0 = Fq::from_be_bytes_mod_order(&data[64..96]);
        let b_x1 = Fq::from_be_bytes_mod_order(&data[96..128]);
        let b_y0 = Fq::from_be_bytes_mod_order(&data[128..160]);
        let b_y1 = Fq::from_be_bytes_mod_order(&data[160..192]);
        let b = G2Affine::new_unchecked(
            ark_bn254::Fq2::new(b_x0, b_x1),
            ark_bn254::Fq2::new(b_y0, b_y1),
        );
        
        // Parse G1 point C (64 bytes)
        let c_x = Fq::from_be_bytes_mod_order(&data[192..224]);
        let c_y = Fq::from_be_bytes_mod_order(&data[224..256]);
        let c = G1Affine::new_unchecked(c_x, c_y);
        
        Ok(ZKProof { a, b, c })
    }
}

#[cfg(any(feature = "verifier", feature = "vkeys"))]
impl VerifyingKey {
    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        // Expected format: alpha_g1 (64) + beta_g2 (128) + gamma_g2 (128) + delta_g2 (128) + 
        // gamma_abc_length (4) + gamma_abc_points (64 * length)
        if data.len() < 452 { // 64 + 128 + 128 + 128 + 4 = 452 minimum
            return Err("Invalid verifying key length");
        }
        
        let mut offset = 0;
        
        // Parse alpha G1 (64 bytes)
        let alpha_x = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
        let alpha_y = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
        let alpha_g1 = G1Affine::new_unchecked(alpha_x, alpha_y);
        offset += 64;
        
        // Parse beta G2 (128 bytes)
        let beta_x0 = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
        let beta_x1 = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
        let beta_y0 = Fq::from_be_bytes_mod_order(&data[offset + 64..offset + 96]);
        let beta_y1 = Fq::from_be_bytes_mod_order(&data[offset + 96..offset + 128]);
        let beta_g2 = G2Affine::new_unchecked(
            Fq2::new(beta_x0, beta_x1),
            Fq2::new(beta_y0, beta_y1),
        );
        offset += 128;
        
        // Parse gamma G2 (128 bytes)
        let gamma_x0 = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
        let gamma_x1 = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
        let gamma_y0 = Fq::from_be_bytes_mod_order(&data[offset + 64..offset + 96]);
        let gamma_y1 = Fq::from_be_bytes_mod_order(&data[offset + 96..offset + 128]);
        let gamma_g2 = G2Affine::new_unchecked(
            Fq2::new(gamma_x0, gamma_x1),
            Fq2::new(gamma_y0, gamma_y1),
        );
        offset += 128;
        
        // Parse delta G2 (128 bytes)
        let delta_x0 = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
        let delta_x1 = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
        let delta_y0 = Fq::from_be_bytes_mod_order(&data[offset + 64..offset + 96]);
        let delta_y1 = Fq::from_be_bytes_mod_order(&data[offset + 96..offset + 128]);
        let delta_g2 = G2Affine::new_unchecked(
            Fq2::new(delta_x0, delta_x1),
            Fq2::new(delta_y0, delta_y1),
        );
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
            let x = Fq::from_be_bytes_mod_order(&data[offset..offset + 32]);
            let y = Fq::from_be_bytes_mod_order(&data[offset + 32..offset + 64]);
            gamma_abc_g1.push(G1Affine::new_unchecked(x, y));
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

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // Serialize alpha G1 (64 bytes)
        let alpha_x_bytes = self.alpha_g1.x.into_bigint().to_bytes_be();
        let alpha_y_bytes = self.alpha_g1.y.into_bigint().to_bytes_be();
        data.extend_from_slice(&alpha_x_bytes[..32]);
        data.extend_from_slice(&alpha_y_bytes[..32]);
        
        // Serialize beta G2 (128 bytes)
        let beta_x0_bytes = self.beta_g2.x.c0.into_bigint().to_bytes_be();
        let beta_x1_bytes = self.beta_g2.x.c1.into_bigint().to_bytes_be();
        let beta_y0_bytes = self.beta_g2.y.c0.into_bigint().to_bytes_be();
        let beta_y1_bytes = self.beta_g2.y.c1.into_bigint().to_bytes_be();
        data.extend_from_slice(&beta_x0_bytes[..32]);
        data.extend_from_slice(&beta_x1_bytes[..32]);
        data.extend_from_slice(&beta_y0_bytes[..32]);
        data.extend_from_slice(&beta_y1_bytes[..32]);
        
        // Serialize gamma G2 (128 bytes)
        let gamma_x0_bytes = self.gamma_g2.x.c0.into_bigint().to_bytes_be();
        let gamma_x1_bytes = self.gamma_g2.x.c1.into_bigint().to_bytes_be();
        let gamma_y0_bytes = self.gamma_g2.y.c0.into_bigint().to_bytes_be();
        let gamma_y1_bytes = self.gamma_g2.y.c1.into_bigint().to_bytes_be();
        data.extend_from_slice(&gamma_x0_bytes[..32]);
        data.extend_from_slice(&gamma_x1_bytes[..32]);
        data.extend_from_slice(&gamma_y0_bytes[..32]);
        data.extend_from_slice(&gamma_y1_bytes[..32]);
        
        // Serialize delta G2 (128 bytes)
        let delta_x0_bytes = self.delta_g2.x.c0.into_bigint().to_bytes_be();
        let delta_x1_bytes = self.delta_g2.x.c1.into_bigint().to_bytes_be();
        let delta_y0_bytes = self.delta_g2.y.c0.into_bigint().to_bytes_be();
        let delta_y1_bytes = self.delta_g2.y.c1.into_bigint().to_bytes_be();
        data.extend_from_slice(&delta_x0_bytes[..32]);
        data.extend_from_slice(&delta_x1_bytes[..32]);
        data.extend_from_slice(&delta_y0_bytes[..32]);
        data.extend_from_slice(&delta_y1_bytes[..32]);
        
        // Serialize gamma ABC length (4 bytes)
        let gamma_abc_len = self.gamma_abc_g1.len() as u32;
        data.extend_from_slice(&gamma_abc_len.to_be_bytes());
        
        // Serialize gamma ABC G1 points (64 * length bytes)
        for point in &self.gamma_abc_g1 {
            let x_bytes = point.x.into_bigint().to_bytes_be();
            let y_bytes = point.y.into_bigint().to_bytes_be();
            data.extend_from_slice(&x_bytes[..32]);
            data.extend_from_slice(&y_bytes[..32]);
        }
        
        data
    }
}

//============================================================================
// VERIFIER CONTRACT
//============================================================================

#[cfg(feature = "verifier")]
sol_storage! {
    #[entrypoint]
    pub struct ZKVerifierContract {
        address owner;
        address vkeys_contract;
    }
}

#[cfg(feature = "verifier")]
#[public]
impl ZKVerifierContract {
    pub fn initialize(&mut self, vkeys_contract: Address) -> Result<(), Vec<u8>> {
        if self.owner.get() != Address::ZERO {
            return Err("Already initialized".into());
        }
        
        self.owner.set(self.vm().msg_sender());
        self.vkeys_contract.set(vkeys_contract);
        Ok(())
    }

    pub fn verify_groth16(
        &self,
        proof_bytes: Vec<u8>,
        public_inputs: Vec<U256>,
    ) -> Result<bool, Vec<u8>> {
        // Parse the ZK proof
        let proof = ZKProof::deserialize(&proof_bytes)?;
        
        // Convert U256 public inputs to Fr
        let mut fr_inputs = Vec::new();
        for input in public_inputs.iter() {
            let bytes: [u8; 32] = input.to_be_bytes();
            let fr_input = Fr::from_be_bytes_mod_order(&bytes);
            fr_inputs.push(fr_input);
        }
        
        // Load verifying key from VKeys contract
        let vk = self.load_verifying_key_from_contract()?;
        
        // Perform verification
        self.groth16_verify(&proof, &vk, &fr_inputs)
    }
    
    pub fn get_vkeys_contract(&self) -> Address {
        self.vkeys_contract.get()
    }
}

#[cfg(feature = "verifier")]
impl ZKVerifierContract {
    fn load_verifying_key_from_contract(&self) -> Result<VerifyingKey, Vec<u8>> {
        let vkeys_address = self.vkeys_contract.get();
        if vkeys_address == Address::ZERO {
            return Err("VKeys contract not set".into());
        }

        // Check if the key is initialized
        let vkeys_contract = IZKVKeys::from(vkeys_address);
        let config = Call::new();
        let is_initialized = vkeys_contract.is_key_initialized(self.vm(), config)?;
        
        if !is_initialized {
            return Err("Verifying key not initialized in VKeys contract".into());
        }

        // Get the verifying key data
        let config = Call::new();
        let vk_data = vkeys_contract.get_verifying_key(self.vm(), config)?;
        
        // Deserialize the verifying key
        VerifyingKey::deserialize(&vk_data).map_err(|e| format!("Failed to deserialize verifying key: {:?}", e).into())
    }

    fn groth16_verify(
        &self,
        proof: &ZKProof,
        vk: &VerifyingKey,
        public_inputs: &[Fr],
    ) -> Result<bool, Vec<u8>> {
        if public_inputs.len() + 1 != vk.gamma_abc_g1.len() {
            return Err("Wrong number of public inputs".into());
        }

        // Compute vk_x = gamma_abc_g1[0] + sum(public_inputs[i] * gamma_abc_g1[i+1])
        let mut vk_x = vk.gamma_abc_g1[0];
        
        for (i, input) in public_inputs.iter().enumerate() {
            // Use precompile for scalar multiplication
            let gamma_abc_term = PrecompileBackend::ec_mul(&*self.vm(), *input, vk.gamma_abc_g1[i + 1])?;
            // Use precompile for point addition
            vk_x = PrecompileBackend::ec_add(&*self.vm(), vk_x, gamma_abc_term)?;
        }

        // Perform pairing check: e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
        // This is equivalent to: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1
        
        // Negate some points for the pairing check
        let neg_alpha = -vk.alpha_g1;
        let neg_vk_x = -vk_x;
        let neg_c = -proof.c;

        // Perform single 4-way pairing check for Groth16
        // Verify: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1
        let mut calldata = [0u8; 768]; // 4 pairs * 192 bytes each
        
        // Serialize all 4 pairs for the pairing precompile
        PrecompileBackend::serialize_g1_point(&proof.a, &mut calldata[0..64]);
        PrecompileBackend::serialize_g2_point(&proof.b, &mut calldata[64..192]);
        PrecompileBackend::serialize_g1_point(&neg_alpha, &mut calldata[192..256]);
        PrecompileBackend::serialize_g2_point(&vk.beta_g2, &mut calldata[256..384]);
        PrecompileBackend::serialize_g1_point(&neg_vk_x, &mut calldata[384..448]);
        PrecompileBackend::serialize_g2_point(&vk.gamma_g2, &mut calldata[448..576]);
        PrecompileBackend::serialize_g1_point(&neg_c, &mut calldata[576..640]);
        PrecompileBackend::serialize_g2_point(&vk.delta_g2, &mut calldata[640..768]);
        
        // Call ecPairing precompile with all 4 pairs
        let result = unsafe {
            RawCall::new(&*self.vm())
                .call(Address::with_last_byte(EC_PAIRING_PRECOMPILE), &calldata)
                .map_err(|_| "ecPairing precompile failed".as_bytes().to_vec())?
        };
        
        // Result is 32 bytes, return true if last byte is 1
        Ok(result.len() == 32 && result[31] == 1)
    }
}

//============================================================================
// VKEYS CONTRACT  
//============================================================================

#[cfg(feature = "vkeys")]
sol_storage! {
    #[entrypoint]
    pub struct ZKVKeysContract {
        address owner;
        
        // Groth16 Verifying Key Storage
        bool vk_initialized;
        
        // Alpha G1 point
        bytes32 vk_alpha_g1_x;
        bytes32 vk_alpha_g1_y;
        
        // Beta G2 point  
        bytes32 vk_beta_g2_x0;
        bytes32 vk_beta_g2_x1;
        bytes32 vk_beta_g2_y0;
        bytes32 vk_beta_g2_y1;
        
        // Gamma G2 point
        bytes32 vk_gamma_g2_x0;
        bytes32 vk_gamma_g2_x1;
        bytes32 vk_gamma_g2_y0;
        bytes32 vk_gamma_g2_y1;
        
        // Delta G2 point
        bytes32 vk_delta_g2_x0;
        bytes32 vk_delta_g2_x1;
        bytes32 vk_delta_g2_y0;
        bytes32 vk_delta_g2_y1;
        
        // Gamma ABC G1 points (for public inputs)
        uint256 vk_gamma_abc_length;
        mapping(uint256 => bytes32) vk_gamma_abc_g1_x;
        mapping(uint256 => bytes32) vk_gamma_abc_g1_y;
    }
}

#[cfg(feature = "vkeys")]
#[public]
impl ZKVKeysContract {
    pub fn initialize(&mut self) -> Result<(), Vec<u8>> {
        if self.owner.get() != Address::ZERO {
            return Err("Already initialized".into());
        }
        
        self.owner.set(self.vm().msg_sender());
        Ok(())
    }

    pub fn set_verifying_key(&mut self, vk_data: Vec<u8>) -> Result<(), Vec<u8>> {
        if self.vm().msg_sender() != self.owner.get() {
            return Err("Only owner can set verifying key".into());
        }

        let vk = VerifyingKey::deserialize(&vk_data)?;

        // Store alpha G1
        let alpha_x_bytes: [u8; 32] = vk.alpha_g1.x.into_bigint().to_bytes_be().try_into().unwrap();
        let alpha_y_bytes: [u8; 32] = vk.alpha_g1.y.into_bigint().to_bytes_be().try_into().unwrap();
        self.vk_alpha_g1_x.set(alpha_x_bytes.into());
        self.vk_alpha_g1_y.set(alpha_y_bytes.into());

        // Store beta G2
        let beta_x0_bytes: [u8; 32] = vk.beta_g2.x.c0.into_bigint().to_bytes_be().try_into().unwrap();
        let beta_x1_bytes: [u8; 32] = vk.beta_g2.x.c1.into_bigint().to_bytes_be().try_into().unwrap();
        let beta_y0_bytes: [u8; 32] = vk.beta_g2.y.c0.into_bigint().to_bytes_be().try_into().unwrap();
        let beta_y1_bytes: [u8; 32] = vk.beta_g2.y.c1.into_bigint().to_bytes_be().try_into().unwrap();
        self.vk_beta_g2_x0.set(beta_x0_bytes.into());
        self.vk_beta_g2_x1.set(beta_x1_bytes.into());
        self.vk_beta_g2_y0.set(beta_y0_bytes.into());
        self.vk_beta_g2_y1.set(beta_y1_bytes.into());

        // Store gamma G2
        let gamma_x0_bytes: [u8; 32] = vk.gamma_g2.x.c0.into_bigint().to_bytes_be().try_into().unwrap();
        let gamma_x1_bytes: [u8; 32] = vk.gamma_g2.x.c1.into_bigint().to_bytes_be().try_into().unwrap();
        let gamma_y0_bytes: [u8; 32] = vk.gamma_g2.y.c0.into_bigint().to_bytes_be().try_into().unwrap();
        let gamma_y1_bytes: [u8; 32] = vk.gamma_g2.y.c1.into_bigint().to_bytes_be().try_into().unwrap();
        self.vk_gamma_g2_x0.set(gamma_x0_bytes.into());
        self.vk_gamma_g2_x1.set(gamma_x1_bytes.into());
        self.vk_gamma_g2_y0.set(gamma_y0_bytes.into());
        self.vk_gamma_g2_y1.set(gamma_y1_bytes.into());

        // Store delta G2
        let delta_x0_bytes: [u8; 32] = vk.delta_g2.x.c0.into_bigint().to_bytes_be().try_into().unwrap();
        let delta_x1_bytes: [u8; 32] = vk.delta_g2.x.c1.into_bigint().to_bytes_be().try_into().unwrap();
        let delta_y0_bytes: [u8; 32] = vk.delta_g2.y.c0.into_bigint().to_bytes_be().try_into().unwrap();
        let delta_y1_bytes: [u8; 32] = vk.delta_g2.y.c1.into_bigint().to_bytes_be().try_into().unwrap();
        self.vk_delta_g2_x0.set(delta_x0_bytes.into());
        self.vk_delta_g2_x1.set(delta_x1_bytes.into());
        self.vk_delta_g2_y0.set(delta_y0_bytes.into());
        self.vk_delta_g2_y1.set(delta_y1_bytes.into());

        // Store gamma ABC length and points
        self.vk_gamma_abc_length.set(U256::from(vk.gamma_abc_g1.len()));
        for (i, point) in vk.gamma_abc_g1.iter().enumerate() {
            let x_bytes: [u8; 32] = point.x.into_bigint().to_bytes_be().try_into().unwrap();
            let y_bytes: [u8; 32] = point.y.into_bigint().to_bytes_be().try_into().unwrap();
            self.vk_gamma_abc_g1_x.setter(U256::from(i)).set(x_bytes.into());
            self.vk_gamma_abc_g1_y.setter(U256::from(i)).set(y_bytes.into());
        }

        self.vk_initialized.set(true);
        Ok(())
    }

    pub fn get_verifying_key(&self) -> Result<Vec<u8>, Vec<u8>> {
        if !self.vk_initialized.get() {
            return Err("Verifying key not initialized".into());
        }

        // Reconstruct alpha G1
        let alpha_x_bytes: [u8; 32] = self.vk_alpha_g1_x.get().into();
        let alpha_y_bytes: [u8; 32] = self.vk_alpha_g1_y.get().into();
        let alpha_x = Fq::from_be_bytes_mod_order(&alpha_x_bytes);
        let alpha_y = Fq::from_be_bytes_mod_order(&alpha_y_bytes);
        let alpha_g1 = G1Affine::new(alpha_x, alpha_y);

        // Reconstruct beta G2
        let beta_x0_bytes: [u8; 32] = self.vk_beta_g2_x0.get().into();
        let beta_x1_bytes: [u8; 32] = self.vk_beta_g2_x1.get().into();
        let beta_y0_bytes: [u8; 32] = self.vk_beta_g2_y0.get().into();
        let beta_y1_bytes: [u8; 32] = self.vk_beta_g2_y1.get().into();
        let beta_x0 = Fq::from_be_bytes_mod_order(&beta_x0_bytes);
        let beta_x1 = Fq::from_be_bytes_mod_order(&beta_x1_bytes);
        let beta_y0 = Fq::from_be_bytes_mod_order(&beta_y0_bytes);
        let beta_y1 = Fq::from_be_bytes_mod_order(&beta_y1_bytes);
        let beta_g2 = G2Affine::new(Fq2::new(beta_x0, beta_x1), Fq2::new(beta_y0, beta_y1));

        // Reconstruct gamma G2
        let gamma_x0_bytes: [u8; 32] = self.vk_gamma_g2_x0.get().into();
        let gamma_x1_bytes: [u8; 32] = self.vk_gamma_g2_x1.get().into();
        let gamma_y0_bytes: [u8; 32] = self.vk_gamma_g2_y0.get().into();
        let gamma_y1_bytes: [u8; 32] = self.vk_gamma_g2_y1.get().into();
        let gamma_x0 = Fq::from_be_bytes_mod_order(&gamma_x0_bytes);
        let gamma_x1 = Fq::from_be_bytes_mod_order(&gamma_x1_bytes);
        let gamma_y0 = Fq::from_be_bytes_mod_order(&gamma_y0_bytes);
        let gamma_y1 = Fq::from_be_bytes_mod_order(&gamma_y1_bytes);
        let gamma_g2 = G2Affine::new(Fq2::new(gamma_x0, gamma_x1), Fq2::new(gamma_y0, gamma_y1));

        // Reconstruct delta G2
        let delta_x0_bytes: [u8; 32] = self.vk_delta_g2_x0.get().into();
        let delta_x1_bytes: [u8; 32] = self.vk_delta_g2_x1.get().into();
        let delta_y0_bytes: [u8; 32] = self.vk_delta_g2_y0.get().into();
        let delta_y1_bytes: [u8; 32] = self.vk_delta_g2_y1.get().into();
        let delta_x0 = Fq::from_be_bytes_mod_order(&delta_x0_bytes);
        let delta_x1 = Fq::from_be_bytes_mod_order(&delta_x1_bytes);
        let delta_y0 = Fq::from_be_bytes_mod_order(&delta_y0_bytes);
        let delta_y1 = Fq::from_be_bytes_mod_order(&delta_y1_bytes);
        let delta_g2 = G2Affine::new(Fq2::new(delta_x0, delta_x1), Fq2::new(delta_y0, delta_y1));

        // Reconstruct gamma ABC G1 points
        let gamma_abc_length = self.vk_gamma_abc_length.get();
        let mut gamma_abc_g1 = Vec::new();
        
        for i in 0..gamma_abc_length.as_limbs()[0] as u32 {
            let x_bytes: [u8; 32] = self.vk_gamma_abc_g1_x.get(U256::from(i)).into();
            let y_bytes: [u8; 32] = self.vk_gamma_abc_g1_y.get(U256::from(i)).into();
            let x = Fq::from_be_bytes_mod_order(&x_bytes);
            let y = Fq::from_be_bytes_mod_order(&y_bytes);
            let point = G1Affine::new(x, y);
            gamma_abc_g1.push(point);
        }

        // Create the VerifyingKey struct
        let vk = VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        };

        // Serialize the verifying key
        let vk_bytes = vk.serialize();
        
        Ok(vk_bytes)
    }
    
    pub fn is_verifying_key_set(&self) -> bool {
        self.vk_initialized.get()
    }
    
    pub fn is_key_initialized(&self) -> bool {
        self.vk_initialized.get()
    }
}

//============================================================================
// NFT CONTRACT
//============================================================================

#[cfg(feature = "nft")]
sol_storage! {
    #[entrypoint]
    pub struct ZKMintNFTContract {
        address owner;
        uint256 next_token_id;
        mapping(uint256 => address) token_owners;
        mapping(address => uint256) token_balances;
        mapping(uint256 => address) token_approvals;
        mapping(address => mapping(address => bool)) operator_approvals;
        
        // External contract addresses
        address verifier_contract;
        address vkeys_contract;
    }
}

#[cfg(feature = "nft")]
#[public]
impl ZKMintNFTContract {
    pub fn initialize(&mut self, verifier_contract: Address, vkeys_contract: Address) -> Result<(), Vec<u8>> {
        if self.owner.get() != Address::ZERO {
            return Err("Already initialized".into());
        }
        
        self.owner.set(self.vm().msg_sender());
        self.next_token_id.set(U256::from(1));
        self.verifier_contract.set(verifier_contract);
        self.vkeys_contract.set(vkeys_contract);
        Ok(())
    }

    pub fn mint_with_zk_proof(
        &mut self,
        to: Address,
        proof_data: Vec<u8>,
        public_inputs: Vec<U256>,
    ) -> Result<U256, Vec<u8>> {
        let verifier_address = self.verifier_contract.get();
        if verifier_address == Address::ZERO {
            return Err("Verifier contract not set".into());
        }

        // Call the verifier contract to verify the ZK proof
        let verifier = IZKVerifier::from(verifier_address);
        let config = Call::new();
        let is_valid = verifier.verify_proof(self.vm(), config, proof_data.into(), public_inputs)?;
        
        if !is_valid {
            return Err("Invalid ZK proof".into());
        }

        // Mint the NFT
        let token_id = self.next_token_id.get();
        self.token_owners.setter(token_id).set(to);
        
        let current_balance = self.token_balances.getter(to).get();
        self.token_balances.setter(to).set(current_balance + U256::from(1));
        
        self.next_token_id.set(token_id + U256::from(1));
        
        Ok(token_id)
    }

    // Standard ERC721 view functions
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
    
    pub fn get_verifier_contract(&self) -> Address {
        self.verifier_contract.get()
    }
    
    pub fn get_vkeys_contract(&self) -> Address {
        self.vkeys_contract.get()
    }
}



#[cfg(feature = "export-abi")]
pub fn print_from_args() {
    stylus_sdk::abi::export()
}