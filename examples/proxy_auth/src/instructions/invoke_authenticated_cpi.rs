use ssi::{
    byte_signed_ix::ByteSignedIx,
    error::SSIError,
    signed_message::{WalletType, SignedInstruction, SignedInstructionSerializoor, WalletInfo},
    utils::serialize_raw,
};
use crate::{
    state::auth_user::AuthUser,
    instructions::ProxyAuthIx,
};

use solana_program::{
    account_info::AccountInfo,
    instruction::{AccountMeta, Instruction},
    log::sol_log as log,
    program::invoke_signed,
    program_error::ProgramError,
    program_pack::Pack,
};

pub fn handle_invoke_authenticated_cpi(
    accounts: &[AccountInfo],
    ix: ProxyAuthIx,
) -> Result<(), ProgramError> {
    let ProxyAuthIx::InvokeAuthenticatedCPI {
        ix_data: _,
        signed_message,
    } = ix
    else {
        return Err(ProgramError::InvalidArgument);
    };

    let auth_user = accounts.get(1).unwrap();
    if auth_user.owner.ne(&crate::ID) {
        return Err(ProgramError::IllegalOwner);
    }

    let auth_user_info = AuthUser::unpack(&auth_user.data.borrow())?;
    let derived_auth_user = auth_user_info.parse_pda();
    if auth_user.key.ne(&derived_auth_user) {
        log("invalid pda");
        return Err(ProgramError::InvalidSeeds);
    }
    let ix_data = {
        let byte_signed_ix = ByteSignedIx {
            instruction: Box::new(ix),
        };
        let recovered_signer = byte_signed_ix.recover_signer(signed_message)?;
        let recovered_signer = ssi::utils::convert_recovered_public_key(recovered_signer)?;

        match auth_user_info.wallet_type {
            WalletType::Ethereum => {
                let constructed_key =
                    signed_message.compare_and_construct_eth_pubkey(WalletInfo {
                        wallet_type: WalletType::Ethereum,
                        raw_public_key: serialize_raw(recovered_signer),
                    })?;
                if constructed_key.ne(&signed_message.wallet_pubkey[0..20]) {
                    return Err(SSIError::CompareAndConstructMismatchedKey(format!(
                        "constructed_key {:?} != wallet_pubkey {:?}",
                        constructed_key,
                        &signed_message.wallet_pubkey[0..20]
                    ))
                    .into());
                }
            }
            WalletType::Solana => {
                return Err(SSIError::UnsupportedWalletType.into());
            }
        }
        byte_signed_ix.serialize()
    };
    let cpi_program_id = *accounts.get(2).unwrap().key;
    let account_infos = accounts.get(3..).unwrap();
    invoke_signed(
        &Instruction {
            program_id: cpi_program_id,
            accounts: account_infos
                .iter()
                .map(|acct| {
                    if !acct.is_writable {
                        AccountMeta::new_readonly(*acct.key, acct.is_signer)
                    } else {
                        AccountMeta::new(*acct.key, acct.is_signer)
                    }
                })
                .collect(),
            data: ix_data,
        },
        account_infos,
        &[&[
            AuthUser::seed(),
            &auth_user_info.signing_key[..],
            &[auth_user_info.nonce],
        ]],
    )?;
    Ok(())
}
