pub mod invoke_authenticated_cpi;
pub mod register_auth_user;

use solana_program::{log::sol_log as log, program_error::ProgramError};
use std::convert::TryInto;

use ssi::{
    byte_signed_ix::ByteSignedIx,
    signed_message::{SignedInstructionSerializoor, SignedMessage, WalletType},
};

#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub enum ProxyAuthIx {
    RegisterAuthUser {
        ix_data: RegisterAuthUserIx,
        signed_message: SignedMessage,
    },
    InvokeAuthenticatedCPI {
        signed_message: SignedMessage,
        ix_data: Vec<u8>,
    },
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RegisterAuthUserIx {
    pub nonce: u8,
    pub wallet_type: WalletType,
}

impl SignedInstructionSerializoor for ProxyAuthIx {
    fn serialize(&self) -> Vec<u8> {
        match self {
            Self::RegisterAuthUser {
                ix_data,
                signed_message: _,
            } => vec![ix_data.nonce, ix_data.wallet_type as u8],
            Self::InvokeAuthenticatedCPI {
                signed_message: _,
                ix_data,
            } => ix_data.clone(),
        }
    }
}

impl ProxyAuthIx {
    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        let (tag, rest) = input
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        log(&format!("tag {tag}"));
        match *tag {
            0 => {
                let (nonce, rest) = Self::unpack_u8(rest)?;
                let (wallet_type, rest) = Self::unpack_u8(rest)?;
                let (signature, rest) = Self::unpack_bytes64(rest)?;
                let (message_hash, rest) = Self::unpack_bytes32(rest)?;
                let (wallet_pubkey, rest) = Self::unpack_bytes32(rest)?;
                let (recovery_id, _) = Self::unpack_u8(rest)?;
                Ok(Self::RegisterAuthUser {
                    ix_data: RegisterAuthUserIx {
                        nonce,
                        wallet_type: WalletType::from(wallet_type),
                    },
                    signed_message: SignedMessage {
                        signature,
                        message_hash,
                        wallet_pubkey,
                        recovery_id,
                    },
                })
            }
            1 => {
                let (signature, rest) = Self::unpack_bytes64(rest)?;
                let (message_hash, rest) = Self::unpack_bytes32(rest)?;
                let (wallet_pubkey, rest) = Self::unpack_bytes32(rest)?;
                let (recovery_id, rest) = Self::unpack_u8(rest)?;
                Ok(Self::InvokeAuthenticatedCPI {
                    signed_message: SignedMessage {
                        signature,
                        message_hash,
                        wallet_pubkey,
                        recovery_id,
                    },
                    ix_data: rest.to_vec(),
                })
            }
            _ => Err(ProgramError::InvalidArgument),
        }
    }
    pub fn pack(&self) -> Vec<u8> {
        match self {
            Self::RegisterAuthUser {
                ix_data,
                signed_message,
            } => {
                let mut buf = Vec::with_capacity(std::mem::size_of::<Self>());
                buf.push(0);
                buf.push(ix_data.nonce);
                buf.push(ix_data.wallet_type as u8);
                buf.extend_from_slice(&signed_message.signature[..]);
                buf.extend_from_slice(&signed_message.message_hash[..]);
                buf.extend_from_slice(&signed_message.wallet_pubkey[..]);
                buf.push(signed_message.recovery_id);
                buf
            }
            Self::InvokeAuthenticatedCPI {
                signed_message,
                ix_data,
            } => {
                let mut buf = Vec::with_capacity(std::mem::size_of::<Self>() + ix_data.len());
                buf.push(1);
                buf.extend_from_slice(&signed_message.signature[..]);
                buf.extend_from_slice(&signed_message.message_hash[..]);
                buf.extend_from_slice(&signed_message.wallet_pubkey[..]);
                buf.push(signed_message.recovery_id);
                buf.extend_from_slice(ix_data);
                buf
            }
        }
    }

    fn unpack_bytes64(input: &[u8]) -> Result<([u8; 64], &[u8]), ProgramError> {
        if input.len() < 64 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (data, rest) = input.split_at(64);

        let mut bytes_64: [u8; 64] = [0_u8; 64];
        bytes_64.copy_from_slice(data);
        Ok((bytes_64, rest))
    }
    fn unpack_bytes32(input: &[u8]) -> Result<([u8; 32], &[u8]), ProgramError> {
        if input.len() < 32 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let (data, rest) = input.split_at(32);

        let mut bytes_32: [u8; 32] = [0_u8; 32];
        bytes_32.copy_from_slice(data);
        Ok((bytes_32, rest))
    }

    fn unpack_slice(input: &[u8], size: usize) -> Result<(&[u8], &[u8]), ProgramError> {
        if input.len() < size {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(input.split_at(size))
    }

    fn unpack_u8(input: &[u8]) -> Result<(u8, &[u8]), ProgramError> {
        let value = input
            .get(..1)
            .and_then(|slice| slice.try_into().ok())
            .map(u8::from_le_bytes)
            .ok_or(ProgramError::InvalidAccountData)?;
        Ok((value, &input[1..]))
    }

    fn unpack_u64(input: &[u8]) -> Result<(u64, &[u8]), ProgramError> {
        let value = input
            .get(..8)
            .and_then(|slice| slice.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(ProgramError::InvalidInstructionData)?;
        Ok((value, &input[8..]))
    }
}

impl Into<ByteSignedIx> for &ProxyAuthIx {
    fn into(self) -> ByteSignedIx {
        ByteSignedIx {
            instruction: Box::new(self.clone()),
        }
    }
}

#[cfg(test)]
mod test {
    use solana_sdk::pubkey::Pubkey;

    use super::*;
    #[test]
    fn test_register_auth_user_pack_unpack() {
        let key = Pubkey::new_unique();
        let ix = ProxyAuthIx::RegisterAuthUser {
            ix_data: RegisterAuthUserIx {
                nonce: 69,
                wallet_type: WalletType::Ethereum,
            },
            signed_message: SignedMessage {
                signature: [69_u8; 64],
                message_hash: [42_u8; 32],
                wallet_pubkey: key.to_bytes(),
                recovery_id: 22,
            },
        };
        let packed_ix = ix.pack();
        let unpacked_ix = ProxyAuthIx::unpack(&packed_ix[..]).unwrap();

        assert_eq!(ix, unpacked_ix);
    }
    #[test]
    fn test_invoke_authenticated_cpi_pack_unpack() {
        let key = Pubkey::new_unique();
        let ix = ProxyAuthIx::InvokeAuthenticatedCPI {
            signed_message: SignedMessage {
                signature: [69_u8; 64],
                message_hash: [42_u8; 32],
                wallet_pubkey: key.to_bytes(),
                recovery_id: 22,
            },
            ix_data: vec![1, 3, 3, 7, 6, 9, 4, 2, 0, 6, 6, 6],
        };
        let packed_ix = ix.pack();
        let unpacked_ix = ProxyAuthIx::unpack(&packed_ix[..]).unwrap();
        assert_eq!(ix, unpacked_ix);
    }
}
