//! Sandbox policy definitions

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Sandbox policy configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Paths with read access
    pub read_paths: Vec<PathPermission>,
    /// Paths with write access
    pub write_paths: Vec<PathPermission>,
    /// Paths with execute access
    pub exec_paths: Vec<PathPermission>,
    /// Network access policy
    pub network: NetworkPolicy,
    /// Execution timeout
    pub timeout: Option<Duration>,
    /// Allow process spawning
    pub allow_spawn: bool,
    /// Environment variables to pass through
    pub env_passthrough: Vec<String>,
    /// Additional policy flags
    pub flags: PolicyFlags,
}

/// Permission for a specific path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPermission {
    /// The path
    pub path: PathBuf,
    /// Whether to include subdirectories
    pub recursive: bool,
}

impl PathPermission {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            recursive: true,
        }
    }

    pub fn non_recursive(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            recursive: false,
        }
    }
}

/// Network access policy
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkPolicy {
    /// No network access
    #[default]
    None,
    /// Localhost only (127.0.0.1, ::1)
    Localhost,
    /// Specific hosts/ports allowed
    Allowlist(Vec<NetworkRule>),
    /// Full network access
    Full,
}

/// Network access rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Host (IP or domain)
    pub host: String,
    /// Port (None = all ports)
    pub port: Option<u16>,
    /// Protocol (tcp, udp, or both)
    pub protocol: NetworkProtocol,
}

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NetworkProtocol {
    #[default]
    Both,
    Tcp,
    Udp,
}

/// Additional policy flags
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyFlags {
    /// Allow reading system files (/etc, /usr, etc.)
    pub allow_system_read: bool,
    /// Allow temporary file creation
    pub allow_tmp: bool,
    /// Allow home directory access
    pub allow_home: bool,
    /// Allow device access (/dev)
    pub allow_devices: bool,
}

impl SandboxPolicy {
    /// Create a new empty policy
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a restrictive default policy for agent tools
    pub fn default_for_tools(cwd: PathBuf) -> Self {
        Self {
            read_paths: vec![
                PathPermission::new(&cwd),
                PathPermission::new("/usr"),
                PathPermission::new("/lib"),
                PathPermission::new("/lib64"),
            ],
            write_paths: vec![
                PathPermission::new(&cwd),
            ],
            exec_paths: vec![
                PathPermission::new("/usr/bin"),
                PathPermission::new("/bin"),
                PathPermission::new("/usr/local/bin"),
            ],
            network: NetworkPolicy::None,
            timeout: Some(Duration::from_secs(120)),
            allow_spawn: true,
            env_passthrough: vec![
                "PATH".into(),
                "HOME".into(),
                "USER".into(),
                "SHELL".into(),
                "TERM".into(),
                "LANG".into(),
            ],
            flags: PolicyFlags {
                allow_system_read: true,
                allow_tmp: true,
                allow_home: false,
                allow_devices: false,
            },
        }
    }

    /// Allow reading a path
    pub fn allow_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_paths.push(PathPermission::new(path));
        self
    }

    /// Allow writing a path
    pub fn allow_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.write_paths.push(PathPermission::new(path));
        self
    }

    /// Allow executing from a path
    pub fn allow_exec(mut self, path: impl Into<PathBuf>) -> Self {
        self.exec_paths.push(PathPermission::new(path));
        self
    }

    /// Set network policy
    pub fn with_network(mut self, policy: NetworkPolicy) -> Self {
        self.network = policy;
        self
    }

    /// Deny all network access
    pub fn deny_network(mut self) -> Self {
        self.network = NetworkPolicy::None;
        self
    }

    /// Allow localhost network access
    pub fn allow_localhost(mut self) -> Self {
        self.network = NetworkPolicy::Localhost;
        self
    }

    /// Allow full network access
    pub fn allow_full_network(mut self) -> Self {
        self.network = NetworkPolicy::Full;
        self
    }

    /// Set execution timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Allow process spawning
    pub fn allow_spawn(mut self, allow: bool) -> Self {
        self.allow_spawn = allow;
        self
    }

    /// Pass through environment variable
    pub fn pass_env(mut self, var: impl Into<String>) -> Self {
        self.env_passthrough.push(var.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Policy Builder Tests ===

    #[test]
    fn test_policy_new() {
        let policy = SandboxPolicy::new();
        assert!(policy.read_paths.is_empty());
        assert!(policy.write_paths.is_empty());
        assert_eq!(policy.network, NetworkPolicy::None);
        assert!(!policy.allow_spawn);
    }

    #[test]
    fn test_policy_builder() {
        let policy = SandboxPolicy::new()
            .allow_read("/usr")
            .allow_write("./src")
            .deny_network()
            .with_timeout(Duration::from_secs(60));

        assert_eq!(policy.read_paths.len(), 1);
        assert_eq!(policy.write_paths.len(), 1);
        assert_eq!(policy.network, NetworkPolicy::None);
        assert_eq!(policy.timeout, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_policy_builder_chaining() {
        let policy = SandboxPolicy::new()
            .allow_read("/usr")
            .allow_read("/lib")
            .allow_write("./src")
            .allow_write("./tests")
            .allow_exec("/usr/bin")
            .allow_spawn(true)
            .pass_env("PATH")
            .pass_env("HOME")
            .with_timeout(Duration::from_secs(120));

        assert_eq!(policy.read_paths.len(), 2);
        assert_eq!(policy.write_paths.len(), 2);
        assert_eq!(policy.exec_paths.len(), 1);
        assert!(policy.allow_spawn);
        assert_eq!(policy.env_passthrough.len(), 2);
    }

    // === Default for Tools Tests ===

    #[test]
    fn test_default_for_tools() {
        let policy = SandboxPolicy::default_for_tools(PathBuf::from("/home/user/project"));
        
        assert!(!policy.read_paths.is_empty());
        assert!(!policy.write_paths.is_empty());
        assert_eq!(policy.network, NetworkPolicy::None);
        assert!(policy.timeout.is_some());
        assert!(policy.allow_spawn);
    }

    #[test]
    fn test_default_for_tools_includes_cwd() {
        let cwd = PathBuf::from("/my/project");
        let policy = SandboxPolicy::default_for_tools(cwd.clone());
        
        let has_cwd_read = policy.read_paths.iter().any(|p| p.path == cwd);
        let has_cwd_write = policy.write_paths.iter().any(|p| p.path == cwd);
        
        assert!(has_cwd_read, "Policy should allow reading cwd");
        assert!(has_cwd_write, "Policy should allow writing to cwd");
    }

    #[test]
    fn test_default_for_tools_has_system_paths() {
        let policy = SandboxPolicy::default_for_tools(PathBuf::from("/project"));
        
        let has_usr = policy.read_paths.iter().any(|p| p.path == PathBuf::from("/usr"));
        assert!(has_usr, "Should have /usr read access");
    }

    // === Network Policy Tests ===

    #[test]
    fn test_deny_network() {
        let policy = SandboxPolicy::new().deny_network();
        assert_eq!(policy.network, NetworkPolicy::None);
    }

    #[test]
    fn test_allow_localhost() {
        let policy = SandboxPolicy::new().allow_localhost();
        assert_eq!(policy.network, NetworkPolicy::Localhost);
    }

    #[test]
    fn test_allow_full_network() {
        let policy = SandboxPolicy::new().allow_full_network();
        assert_eq!(policy.network, NetworkPolicy::Full);
    }

    #[test]
    fn test_with_network_allowlist() {
        let policy = SandboxPolicy::new()
            .with_network(NetworkPolicy::Allowlist(vec![
                NetworkRule {
                    host: "api.example.com".into(),
                    port: Some(443),
                    protocol: NetworkProtocol::Tcp,
                },
            ]));
        
        match policy.network {
            NetworkPolicy::Allowlist(rules) => {
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].host, "api.example.com");
            }
            _ => panic!("Expected allowlist"),
        }
    }

    // === PathPermission Tests ===

    #[test]
    fn test_path_permission_new() {
        let perm = PathPermission::new("/usr/lib");
        assert_eq!(perm.path, PathBuf::from("/usr/lib"));
        assert!(perm.recursive);
    }

    #[test]
    fn test_path_permission_non_recursive() {
        let perm = PathPermission::non_recursive("/etc/passwd");
        assert_eq!(perm.path, PathBuf::from("/etc/passwd"));
        assert!(!perm.recursive);
    }

    // === NetworkPolicy Tests ===

    #[test]
    fn test_network_policy_default() {
        let policy: NetworkPolicy = Default::default();
        assert_eq!(policy, NetworkPolicy::None);
    }

    #[test]
    fn test_network_policy_variants() {
        let policies = vec![
            NetworkPolicy::None,
            NetworkPolicy::Localhost,
            NetworkPolicy::Full,
            NetworkPolicy::Allowlist(vec![]),
        ];
        
        for policy in policies {
            let json = serde_json::to_string(&policy).unwrap();
            let parsed: NetworkPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, policy);
        }
    }

    // === NetworkRule Tests ===

    #[test]
    fn test_network_rule() {
        let rule = NetworkRule {
            host: "localhost".into(),
            port: Some(8080),
            protocol: NetworkProtocol::Tcp,
        };
        
        assert_eq!(rule.host, "localhost");
        assert_eq!(rule.port, Some(8080));
        assert_eq!(rule.protocol, NetworkProtocol::Tcp);
    }

    #[test]
    fn test_network_rule_no_port() {
        let rule = NetworkRule {
            host: "*.example.com".into(),
            port: None,
            protocol: NetworkProtocol::Both,
        };
        
        assert!(rule.port.is_none());
    }

    // === NetworkProtocol Tests ===

    #[test]
    fn test_network_protocol_default() {
        let protocol: NetworkProtocol = Default::default();
        assert_eq!(protocol, NetworkProtocol::Both);
    }

    #[test]
    fn test_network_protocol_variants() {
        let protocols = vec![
            NetworkProtocol::Both,
            NetworkProtocol::Tcp,
            NetworkProtocol::Udp,
        ];
        
        for protocol in protocols {
            let json = serde_json::to_string(&protocol).unwrap();
            let parsed: NetworkProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, protocol);
        }
    }

    // === PolicyFlags Tests ===

    #[test]
    fn test_policy_flags_default() {
        let flags: PolicyFlags = Default::default();
        assert!(!flags.allow_system_read);
        assert!(!flags.allow_tmp);
        assert!(!flags.allow_home);
        assert!(!flags.allow_devices);
    }

    #[test]
    fn test_policy_flags_custom() {
        let flags = PolicyFlags {
            allow_system_read: true,
            allow_tmp: true,
            allow_home: false,
            allow_devices: false,
        };
        
        assert!(flags.allow_system_read);
        assert!(flags.allow_tmp);
        assert!(!flags.allow_home);
    }

    // === Serialization Tests ===

    #[test]
    fn test_sandbox_policy_serialization() {
        let policy = SandboxPolicy::new()
            .allow_read("/usr")
            .allow_write("./src")
            .with_timeout(Duration::from_secs(60));
        
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: SandboxPolicy = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.read_paths.len(), 1);
        assert_eq!(parsed.write_paths.len(), 1);
        assert_eq!(parsed.timeout, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_path_permission_serialization() {
        let perm = PathPermission::new("/test/path");
        let json = serde_json::to_string(&perm).unwrap();
        let parsed: PathPermission = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.path, PathBuf::from("/test/path"));
        assert!(parsed.recursive);
    }

    // === Timeout Tests ===

    #[test]
    fn test_with_timeout() {
        let policy = SandboxPolicy::new()
            .with_timeout(Duration::from_secs(300));
        
        assert_eq!(policy.timeout, Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_no_timeout() {
        let policy = SandboxPolicy::new();
        assert!(policy.timeout.is_none());
    }

    // === Environment Passthrough Tests ===

    #[test]
    fn test_pass_env() {
        let policy = SandboxPolicy::new()
            .pass_env("PATH")
            .pass_env("HOME")
            .pass_env("USER");
        
        assert_eq!(policy.env_passthrough.len(), 3);
        assert!(policy.env_passthrough.contains(&"PATH".to_string()));
    }

    // === Allow Spawn Tests ===

    #[test]
    fn test_allow_spawn_default() {
        let policy = SandboxPolicy::new();
        assert!(!policy.allow_spawn);
    }

    #[test]
    fn test_allow_spawn_enabled() {
        let policy = SandboxPolicy::new().allow_spawn(true);
        assert!(policy.allow_spawn);
    }

    #[test]
    fn test_allow_spawn_disabled() {
        let policy = SandboxPolicy::new()
            .allow_spawn(true)
            .allow_spawn(false);
        assert!(!policy.allow_spawn);
    }
}
