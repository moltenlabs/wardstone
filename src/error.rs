//! Sandbox error types

use thiserror::Error;

/// Errors that can occur during sandbox operations
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Sandbox not available on this platform
    #[error("Sandbox not available: {0}")]
    NotAvailable(String),

    /// Failed to create sandbox policy
    #[error("Policy error: {0}")]
    PolicyError(String),

    /// Failed to apply sandbox
    #[error("Failed to apply sandbox: {0}")]
    ApplyError(String),

    /// Permission denied by sandbox
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
