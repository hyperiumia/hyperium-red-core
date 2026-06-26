use thiserror::Error;

#[derive(Error, Debug)]
pub enum RedCoreError {
    #[error("Target not in authorized scope: {0}")]
    TargetNotInScope(String),

    #[error("No authorization configured. Run with --authorize first")]
    NoAuthorization,

    #[error("Connection failed to {target}:{port} - {reason}")]
    ConnectionFailed { target: String, port: u16, reason: String },

    #[error("Technique {technique_id} failed on {target}: {reason}")]
    TechniqueFailed { technique_id: String, target: String, reason: String },

    #[error("Evidence chain integrity violation: {0}")]
    IntegrityViolation(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Safe mode blocked destructive technique: {0}")]
    SafeModeBlocked(String),
}
