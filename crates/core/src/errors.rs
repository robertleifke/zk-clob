use core::fmt;

#[derive(Debug)]
pub enum CoreError {
    Decode(&'static str),
    Invalid(&'static str),
    Math(&'static str),
    Signature(&'static str),
    State(&'static str),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Decode(msg) => write!(f, "decode error: {msg}"),
            CoreError::Invalid(msg) => write!(f, "invalid input: {msg}"),
            CoreError::Math(msg) => write!(f, "math error: {msg}"),
            CoreError::Signature(msg) => write!(f, "signature error: {msg}"),
            CoreError::State(msg) => write!(f, "state error: {msg}"),
        }
    }
}
