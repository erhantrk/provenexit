//! Custom program errors (SPEC-CHAINS §11): `ProgramError::Custom(n)` with `n` = the §10 numbering, so clients map
//! the number back to the PLR error code name.
use solana_program::program_error::ProgramError;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PlrError {
    E_UNAUTHORIZED = 1,
    E_ZERO_HASH = 2,
    E_BAD_INPUT = 3,
    E_OPERATOR_UNAPPROVED = 4,
    E_REPORT_DATA = 5,
    E_QUOTE_FORMAT = 6,
    E_SEQ = 7,
    E_INSTANCE_NOT_REGISTERED = 8,
    E_COMPOSE_NOT_ALLOWED = 9,
}

impl PlrError {
    pub const ALL: [PlrError; 9] = [
        PlrError::E_UNAUTHORIZED,
        PlrError::E_ZERO_HASH,
        PlrError::E_BAD_INPUT,
        PlrError::E_OPERATOR_UNAPPROVED,
        PlrError::E_REPORT_DATA,
        PlrError::E_QUOTE_FORMAT,
        PlrError::E_SEQ,
        PlrError::E_INSTANCE_NOT_REGISTERED,
        PlrError::E_COMPOSE_NOT_ALLOWED,
    ];

    pub fn code(self) -> u32 {
        self as u32
    }

    /// The PLR code name (as the TypeScript side spells it).
    pub fn name(self) -> &'static str {
        match self {
            PlrError::E_UNAUTHORIZED => "E_UNAUTHORIZED",
            PlrError::E_ZERO_HASH => "E_ZERO_HASH",
            PlrError::E_BAD_INPUT => "E_BAD_INPUT",
            PlrError::E_OPERATOR_UNAPPROVED => "E_OPERATOR_UNAPPROVED",
            PlrError::E_REPORT_DATA => "E_REPORT_DATA",
            PlrError::E_QUOTE_FORMAT => "E_QUOTE_FORMAT",
            PlrError::E_SEQ => "E_SEQ",
            PlrError::E_INSTANCE_NOT_REGISTERED => "E_INSTANCE_NOT_REGISTERED",
            PlrError::E_COMPOSE_NOT_ALLOWED => "E_COMPOSE_NOT_ALLOWED",
        }
    }
}

impl From<PlrError> for ProgramError {
    fn from(e: PlrError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
