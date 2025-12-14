//! Linux Landlock sandbox implementation

use std::process::Command;
use tracing::{debug, info, warn};

use crate::policy::{SandboxPolicy, NetworkPolicy};
use crate::error::SandboxError;
use crate::Sandbox;

/// Linux Landlock sandbox implementation
pub struct LandlockSandbox {
    policy: SandboxPolicy,
}

impl LandlockSandbox {
    /// Create a new Landlock sandbox with the given policy
    pub fn new(policy: SandboxPolicy) -> Result<Self, SandboxError> {
        // Check if Landlock is supported
        if !Self::is_available() {
            return Err(SandboxError::NotAvailable(
                "Landlock not supported on this kernel".into()
            ));
        }
        
        debug!("Created Landlock sandbox");
        Ok(Self { policy })
    }
}

impl Sandbox for LandlockSandbox {
    fn wrap_command(&self, cmd: Command) -> Result<Command, SandboxError> {
        // For Landlock, we need to use a helper that applies the ruleset
        // before execing the target command.
        //
        // In a full implementation, this would:
        // 1. Create a Landlock ruleset with the policy
        // 2. Fork and apply the ruleset in the child
        // 3. Exec the target command
        //
        // For now, we'll document this as needing the `landlock-sandbox` helper
        
        warn!("Landlock sandbox wrapping not fully implemented - using passthrough");
        
        // In production, this would use something like:
        // let mut sandbox_cmd = Command::new("landlock-sandbox");
        // sandbox_cmd.arg("--policy").arg(policy_file);
        // ... copy original command args ...
        
        Ok(cmd)
    }

    fn is_available() -> bool {
        // Check if Landlock is supported by checking kernel features
        // Landlock requires kernel >= 5.13
        
        use std::fs;
        
        // Check for Landlock ABI
        if let Ok(contents) = fs::read_to_string("/sys/kernel/security/lsm") {
            if contents.contains("landlock") {
                return true;
            }
        }
        
        // Alternative check via prctl (would need libc)
        false
    }

    fn sandbox_type(&self) -> &'static str {
        "landlock"
    }
}

/// Apply Landlock restrictions to the current process
///
/// This should be called after fork() but before exec()
#[cfg(target_os = "linux")]
pub fn apply_landlock_policy(policy: &SandboxPolicy) -> Result<(), SandboxError> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, ABI,
    };
    
    // Create a ruleset with the appropriate ABI
    let abi = ABI::V3; // Use latest stable ABI
    
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| SandboxError::PolicyError(format!("Failed to create ruleset: {}", e)))?;
    
    let ruleset = ruleset.create()
        .map_err(|e| SandboxError::PolicyError(format!("Failed to create ruleset: {}", e)))?;
    
    // Add read rules
    for perm in &policy.read_paths {
        let path = &perm.path;
        if path.exists() {
            if let Ok(fd) = PathFd::new(path) {
                let access = AccessFs::ReadFile | AccessFs::ReadDir;
                let _ = ruleset.add_rule(PathBeneath::new(fd, access));
            }
        }
    }
    
    // Add write rules  
    for perm in &policy.write_paths {
        let path = &perm.path;
        if path.exists() {
            if let Ok(fd) = PathFd::new(path) {
                let access = AccessFs::WriteFile | AccessFs::RemoveFile | 
                            AccessFs::RemoveDir | AccessFs::MakeDir;
                let _ = ruleset.add_rule(PathBeneath::new(fd, access));
            }
        }
    }
    
    // Add execute rules
    for perm in &policy.exec_paths {
        let path = &perm.path;
        if path.exists() {
            if let Ok(fd) = PathFd::new(path) {
                let access = AccessFs::Execute;
                let _ = ruleset.add_rule(PathBeneath::new(fd, access));
            }
        }
    }
    
    // Restrict the process
    ruleset.restrict_self()
        .map_err(|e| SandboxError::PolicyError(format!("Failed to restrict: {}", e)))?;
    
    info!("Applied Landlock restrictions");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_landlock_policy(_policy: &SandboxPolicy) -> Result<(), SandboxError> {
    Err(SandboxError::NotAvailable("Landlock only available on Linux".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_availability_check() {
        // This will depend on the system
        let _ = LandlockSandbox::is_available();
    }
}
