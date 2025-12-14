//! macOS Seatbelt (sandbox-exec) implementation

use std::process::Command;
use tracing::{debug, info};

use crate::policy::{SandboxPolicy, NetworkPolicy, PathPermission};
use crate::error::SandboxError;
use crate::Sandbox;

/// macOS Seatbelt sandbox implementation
pub struct SeatbeltSandbox {
    policy: SandboxPolicy,
    policy_string: String,
}

impl SeatbeltSandbox {
    /// Create a new Seatbelt sandbox with the given policy
    pub fn new(policy: SandboxPolicy) -> Result<Self, SandboxError> {
        let policy_string = generate_seatbelt_policy(&policy)?;
        debug!(policy = %policy_string, "Generated Seatbelt policy");
        
        Ok(Self {
            policy,
            policy_string,
        })
    }

    /// Get the generated policy string
    pub fn policy_string(&self) -> &str {
        &self.policy_string
    }
}

impl Sandbox for SeatbeltSandbox {
    fn wrap_command(&self, mut cmd: Command) -> Result<Command, SandboxError> {
        let mut sandbox_cmd = Command::new("/usr/bin/sandbox-exec");
        sandbox_cmd.arg("-p").arg(&self.policy_string);
        
        // Get the program and args from original command
        let program = cmd.get_program().to_string_lossy().to_string();
        sandbox_cmd.arg(program);
        
        for arg in cmd.get_args() {
            sandbox_cmd.arg(arg);
        }
        
        // Pass through environment
        for var in &self.policy.env_passthrough {
            if let Ok(value) = std::env::var(var) {
                sandbox_cmd.env(var, value);
            }
        }
        
        // Copy working directory
        if let Some(cwd) = cmd.get_current_dir() {
            sandbox_cmd.current_dir(cwd);
        }
        
        info!("Wrapped command with Seatbelt sandbox");
        Ok(sandbox_cmd)
    }

    fn is_available() -> bool {
        // Check if sandbox-exec exists
        std::path::Path::new("/usr/bin/sandbox-exec").exists()
    }

    fn sandbox_type(&self) -> &'static str {
        "seatbelt"
    }
}

/// Generate a Seatbelt policy (.sbpl) string from our policy
fn generate_seatbelt_policy(policy: &SandboxPolicy) -> Result<String, SandboxError> {
    let mut sbpl = String::new();
    
    // Header
    sbpl.push_str("(version 1)\n");
    sbpl.push_str("(deny default)\n\n");
    
    // Allow basic operations
    sbpl.push_str("; Basic operations\n");
    sbpl.push_str("(allow signal (target self))\n");
    sbpl.push_str("(allow sysctl-read)\n");
    sbpl.push_str("(allow mach-lookup)\n");
    sbpl.push_str("(allow ipc-posix-shm-read-data)\n");
    sbpl.push_str("(allow ipc-posix-shm-write-data)\n");
    
    // Process operations
    if policy.allow_spawn {
        sbpl.push_str("\n; Process operations\n");
        sbpl.push_str("(allow process-fork)\n");
        sbpl.push_str("(allow process-exec)\n");
    }
    
    // Read paths
    sbpl.push_str("\n; Read paths\n");
    for perm in &policy.read_paths {
        sbpl.push_str(&format_read_rule(perm));
    }
    
    // System read access
    if policy.flags.allow_system_read {
        sbpl.push_str("(allow file-read* (subpath \"/usr\"))\n");
        sbpl.push_str("(allow file-read* (subpath \"/lib\"))\n");
        sbpl.push_str("(allow file-read* (subpath \"/bin\"))\n");
        sbpl.push_str("(allow file-read* (subpath \"/sbin\"))\n");
        sbpl.push_str("(allow file-read* (subpath \"/System\"))\n");
        sbpl.push_str("(allow file-read* (subpath \"/Library\"))\n");
        sbpl.push_str("(allow file-read* (subpath \"/private/var\"))\n");
    }
    
    // Tmp access
    if policy.flags.allow_tmp {
        sbpl.push_str("(allow file-read* (subpath \"/tmp\"))\n");
        sbpl.push_str("(allow file-write* (subpath \"/tmp\"))\n");
        sbpl.push_str("(allow file-read* (subpath \"/private/tmp\"))\n");
        sbpl.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
    }
    
    // Write paths
    sbpl.push_str("\n; Write paths\n");
    for perm in &policy.write_paths {
        sbpl.push_str(&format_write_rule(perm));
    }
    
    // Execute paths
    sbpl.push_str("\n; Execute paths\n");
    for perm in &policy.exec_paths {
        sbpl.push_str(&format_exec_rule(perm));
    }
    
    // Network
    sbpl.push_str("\n; Network\n");
    match &policy.network {
        NetworkPolicy::None => {
            sbpl.push_str("; Network access denied\n");
        }
        NetworkPolicy::Localhost => {
            sbpl.push_str("(allow network-outbound (local ip \"localhost:*\"))\n");
            sbpl.push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
        }
        NetworkPolicy::Full => {
            sbpl.push_str("(allow network-outbound)\n");
            sbpl.push_str("(allow network-inbound)\n");
        }
        NetworkPolicy::Allowlist(rules) => {
            for rule in rules {
                let port = rule.port.map(|p| format!(":{}", p)).unwrap_or_else(|| ":*".to_string());
                sbpl.push_str(&format!("(allow network-outbound (remote ip \"{}{}\" ))\n", rule.host, port));
            }
        }
    }
    
    Ok(sbpl)
}

fn format_read_rule(perm: &PathPermission) -> String {
    let path = perm.path.to_string_lossy();
    if perm.recursive {
        format!("(allow file-read* (subpath \"{}\"))\n", path)
    } else {
        format!("(allow file-read* (literal \"{}\"))\n", path)
    }
}

fn format_write_rule(perm: &PathPermission) -> String {
    let path = perm.path.to_string_lossy();
    if perm.recursive {
        format!("(allow file-write* (subpath \"{}\"))\n", path)
    } else {
        format!("(allow file-write* (literal \"{}\"))\n", path)
    }
}

fn format_exec_rule(perm: &PathPermission) -> String {
    let path = perm.path.to_string_lossy();
    if perm.recursive {
        format!("(allow process-exec (subpath \"{}\"))\n", path)
    } else {
        format!("(allow process-exec (literal \"{}\"))\n", path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_policy_generation() {
        let policy = SandboxPolicy::default_for_tools(PathBuf::from("/tmp/test"));
        let sbpl = generate_seatbelt_policy(&policy).unwrap();
        
        assert!(sbpl.contains("(version 1)"));
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("/tmp/test"));
    }

    #[test]
    fn test_network_policy() {
        let policy = SandboxPolicy::new().allow_localhost();
        let sbpl = generate_seatbelt_policy(&policy).unwrap();
        
        assert!(sbpl.contains("localhost"));
    }
}
