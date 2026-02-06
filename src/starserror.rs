use std::fmt;

/// StarsError. Contains error messages from the STARS system.
#[derive(Debug, Clone)]
pub struct StarsError {
    pub message: String,
}
// make it printable
impl fmt::Display for StarsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.message)
    }
}
//implement default error definitions
impl std::error::Error for StarsError {}
