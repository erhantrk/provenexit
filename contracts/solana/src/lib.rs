//! PLR registry on Solana (tier B, SPEC-CHAINS §11): one native program; each registry is a state account created
//! by `Init` (`contractId = "solana:" ‖ base58(state)`), with per-item PDAs for allowlists, operators, instances
//! (record + 828-byte registration quote) and anchors. Same rules as the EVM registry (§9); errors are
//! `ProgramError::Custom(n)` with the §10 numbering. The registration quote's signature is not verified on-chain:
//! clients verify it (SPEC-CHAINS §2).
pub mod error;
pub mod instruction;
pub mod processor;
pub mod rules;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey};
    solana_program::entrypoint!(process_instruction);
    fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
        crate::processor::process_instruction(program_id, accounts, data)
    }
}

#[cfg(test)]
mod tests;
