use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use anyhow::Result;

use crate::{Test, TestCategory, TestResult};

pub struct HostMountsTest {}

#[derive(Default)]
pub struct HostMountsResult {
    pub dangerous_mounts: Vec<String>,
    pub writable_host_mounts: Vec<String>,
    pub socket_mounts: Vec<String>,
    pub host_root_mounts: Vec<String>,
}

impl Test for HostMountsTest {
    fn name(&self) -> String {
        "host filesystem mounts".to_string()
    }

    fn run(&self) -> Result<Box<dyn TestResult>, ()> {
        let mut result = HostMountsResult::default();

        // Read /proc/mounts to analyze mounted filesystems
        if let Ok(mounts_content) = fs::read_to_string("/proc/mounts") {
            for line in mounts_content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let device = parts[0];
                    let mount_point = parts[1];
                    let fs_type = parts[2];
                    let options = parts[3];

                    // Check for dangerous mount points
                    let dangerous_paths = [
                        "/",
                        "/etc",
                        "/boot",
                        "/var/run",
                        "/sys",
                        "/proc",
                        "/var/lib/docker",
                        "/var/lib/containerd",
                        "/run",
                        "/usr",
                        "/lib",
                        "/bin",
                        "/sbin",
                        "/opt",
                        "/home",
                    ];

                    for dangerous_path in &dangerous_paths {
                        if mount_point == *dangerous_path {
                            result
                                .dangerous_mounts
                                .push(format!("{} -> {}", device, mount_point));
                        }
                    }

                    // Check for host root filesystem mounts (common indicators)
                    if device.starts_with("/dev/")
                        && (fs_type == "ext4"
                            || fs_type == "xfs"
                            || fs_type == "btrfs"
                            || fs_type == "zfs")
                        && (mount_point == "/" || mount_point.starts_with("/host"))
                    {
                        result
                            .host_root_mounts
                            .push(format!("{} -> {} ({})", device, mount_point, fs_type));
                    }

                    // Check for writable mounts that could be host directories
                    if !options.contains("ro")
                        && (mount_point.starts_with("/host")
                            || mount_point.starts_with("/mnt")
                            || mount_point.starts_with("/media")
                            || (device.starts_with("/")
                                && !device.starts_with("/dev/")
                                && Path::new(device).exists()))
                    {
                        result
                            .writable_host_mounts
                            .push(format!("{} -> {} (writable)", device, mount_point));
                    }

                    // Check for container runtime socket mounts
                    let socket_patterns = [
                        "docker.sock",
                        "containerd.sock",
                        "crio.sock",
                        "podman.sock",
                        "lxd/unix.socket",
                        "kubelet",
                    ];

                    for pattern in &socket_patterns {
                        if device.contains(pattern) || mount_point.contains(pattern) {
                            result
                                .socket_mounts
                                .push(format!("{} -> {}", device, mount_point));
                        }
                    }
                }
            }
        }

        // Also check for specific dangerous files/sockets that might be bind-mounted
        let dangerous_files = [
            "/var/run/docker.sock",
            "/var/run/containerd/containerd.sock",
            "/var/run/crio/crio.sock",
            "/run/docker.sock",
            "/run/containerd/containerd.sock",
        ];

        for file_path in &dangerous_files {
            if Path::new(file_path).exists() {
                // Check if it's a socket
                if let Ok(metadata) = fs::metadata(file_path) {
                    if metadata.file_type().is_socket() {
                        result
                            .socket_mounts
                            .push(format!("socket access: {}", file_path));
                    }
                }
            }
        }

        // Remove duplicates
        result.dangerous_mounts.sort();
        result.dangerous_mounts.dedup();
        result.writable_host_mounts.sort();
        result.writable_host_mounts.dedup();
        result.socket_mounts.sort();
        result.socket_mounts.dedup();
        result.host_root_mounts.sort();
        result.host_root_mounts.dedup();

        Ok(Box::new(result))
    }

    fn category(&self) -> TestCategory {
        TestCategory::High
    }
}

impl TestResult for HostMountsResult {
    fn success(&self) -> bool {
        self.dangerous_mounts.is_empty()
            && self.socket_mounts.is_empty()
            && self.host_root_mounts.is_empty()
            && self.writable_host_mounts.is_empty()
    }

    fn explain(&self) -> String {
        let mut issues = Vec::new();

        if !self.dangerous_mounts.is_empty() {
            issues.push(format!(
                "dangerous system paths mounted: {}",
                self.dangerous_mounts.join(", ")
            ));
        }

        if !self.host_root_mounts.is_empty() {
            issues.push(format!(
                "host root filesystem accessible: {}",
                self.host_root_mounts.join(", ")
            ));
        }

        if !self.socket_mounts.is_empty() {
            issues.push(format!(
                "container runtime sockets accessible: {}",
                self.socket_mounts.join(", ")
            ));
        }

        if !self.writable_host_mounts.is_empty() {
            issues.push(format!(
                "writable host directories mounted: {}",
                self.writable_host_mounts
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if issues.is_empty() {
            "container filesystem isolation is secure".to_string()
        } else {
            format!("container has dangerous host access: {}", issues.join("; "))
        }
    }

    fn as_string(&self) -> String {
        if self.success() {
            "no".to_string()
        } else {
            "yes".to_string()
        }
    }

    fn fault_code(&self) -> String {
        "AII3200".to_string()
    }
}
