//! # Wardstone
//!
//! Sandboxing system for secure tool execution - magical containment.
//!
//! Provides platform-specific sandboxing:
//! - **macOS**: Seatbelt (sandbox-exec) with .sbpl policies
//! - **Linux**: Landlock + seccomp
//! - **Windows**: Windows Sandbox (future)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use wardstone::{Sandbox, SandboxPolicy};
//!
//! let policy = SandboxPolicy::new()
//!     .allow_read("/usr")
//!     .allow_write("./")
//!     .deny_network();
//!
//! let sandbox = Sandbox::new(policy)?;
//! let wrapped_cmd = sandbox.wrap_command(cmd);
//! ```

pub mod policy;
pub mod error;

#[cfg(target_os = "macos")]
pub mod seatbelt;

#[cfg(target_os = "linux")]
pub mod landlock;

#[cfg(windows)]
pub mod windows;

pub use policy::{SandboxPolicy, NetworkPolicy, PathPermission};
pub use error::SandboxError;

use std::process::Command;

/// Platform-specific sandbox implementation
pub trait Sandbox: Send + Sync {
    /// Wrap a command with sandbox restrictions
    fn wrap_command(&self, cmd: Command) -> Result<Command, SandboxError>;
    
    /// Check if sandbox is available on this platform
    fn is_available() -> bool where Self: Sized;
    
    /// Get the sandbox type name
    fn sandbox_type(&self) -> &'static str;
}

/// Create the appropriate sandbox for the current platform
pub fn create_sandbox(policy: SandboxPolicy) -> Result<Box<dyn Sandbox>, SandboxError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(seatbelt::SeatbeltSandbox::new(policy)?))
    }
    
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(landlock::LandlockSandbox::new(policy)?))
    }
    
    #[cfg(windows)]
    {
        // Windows sandbox not yet implemented
        Err(SandboxError::NotAvailable("Windows sandbox not implemented".into()))
    }
    
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Err(SandboxError::NotAvailable("No sandbox available for this platform".into()))
    }
}

/// Check if sandboxing is available on this platform
pub fn is_sandbox_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        seatbelt::SeatbeltSandbox::is_available()
    }
    
    #[cfg(target_os = "linux")]
    {
        landlock::LandlockSandbox::is_available()
    }
    
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}
