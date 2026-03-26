// PLACEHOLDER verifying key implementation
// The setup.sh script will overwrite this file with the actual verification key
// DO NOT EDIT - This is just a stub to allow compilation before setup

use alloc::vec;
use alloc::vec::Vec;
use crate::VerifyingKey;

pub fn get_verifying_key() -> VerifyingKey {
    VerifyingKey {
        alpha_g1: [0u8; 64],
        beta_g2: [0u8; 128],
        gamma_g2: [0u8; 128],
        delta_g2: [0u8; 128],
        gamma_abc_g1: vec![[0u8; 64]; 2],
    }
}
