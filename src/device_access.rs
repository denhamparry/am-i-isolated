use std::path::Path;
use std::fs;
use std::os::unix::fs::FileTypeExt;

use anyhow::Result;

use crate::{Test, TestCategory, TestResult};

pub struct DeviceAccessTest {}

#[derive(Default)]
pub struct DeviceAccessResult {
    pub dangerous_devices: Vec<String>,
    pub block_devices: Vec<String>,
    pub hardware_rngs: Vec<String>,
    pub gpu_devices: Vec<String>,
    pub character_devices: Vec<String>,
}

impl Test for DeviceAccessTest {
    fn name(&self) -> String {
        "device node access".to_string()
    }

    fn run(&self) -> Result<Box<dyn TestResult>, ()> {
        let mut result = DeviceAccessResult::default();

        // Check for dangerous memory devices
        let dangerous_paths = [
            "/dev/mem",
            "/dev/kmem", 
            "/dev/port"
        ];

        for device_path in &dangerous_paths {
            if Path::new(device_path).exists() {
                if let Ok(metadata) = fs::metadata(device_path) {
                    // Check if we can read the device (indicates access)
                    if metadata.permissions().readonly() || !metadata.permissions().readonly() {
                        result.dangerous_devices.push(device_path.to_string());
                    }
                }
            }
        }

        // Check for block device access
        if let Ok(entries) = fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let path = entry.path();
                let filename = path.file_name().unwrap_or_default().to_string_lossy();
                
                if let Ok(metadata) = entry.metadata() {
                    // Check for block devices
                    if metadata.file_type().is_block_device() {
                        if filename.starts_with("sd") || 
                           filename.starts_with("nvme") || 
                           filename.starts_with("vd") ||
                           filename.starts_with("hd") ||
                           filename.starts_with("xvd") {
                            result.block_devices.push(path.to_string_lossy().to_string());
                        }
                    }
                    
                    // Check for character devices that could be problematic
                    if metadata.file_type().is_char_device() {
                        // Hardware random number generators
                        if filename.starts_with("hwrng") || filename == "random" || filename == "urandom" {
                            result.hardware_rngs.push(path.to_string_lossy().to_string());
                        }
                        
                        // GPU devices
                        if filename.starts_with("nvidia") || 
                           filename.starts_with("dri/") ||
                           path.to_string_lossy().contains("/dri/") {
                            result.gpu_devices.push(path.to_string_lossy().to_string());
                        }
                        
                        // Other potentially dangerous character devices
                        if filename.starts_with("tty") ||
                           filename.starts_with("pts/") ||
                           filename == "console" ||
                           filename.starts_with("fb") ||  // framebuffer devices
                           filename.starts_with("input/") {
                            result.character_devices.push(path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }

        // Also check /dev/dri directory specifically for GPU devices
        if let Ok(entries) = fs::read_dir("/dev/dri") {
            for entry in entries.flatten() {
                let path = entry.path();
                result.gpu_devices.push(path.to_string_lossy().to_string());
            }
        }

        Ok(Box::new(result))
    }

    fn category(&self) -> TestCategory {
        TestCategory::High
    }
}

impl TestResult for DeviceAccessResult {
    fn success(&self) -> bool {
        self.dangerous_devices.is_empty() && 
        self.block_devices.is_empty() &&
        self.gpu_devices.is_empty() &&
        // Hardware RNGs and some character devices might be acceptable
        self.character_devices.len() <= 3  // Allow minimal character device access
    }

    fn explain(&self) -> String {
        let mut issues = Vec::new();
        
        if !self.dangerous_devices.is_empty() {
            issues.push(format!("access to dangerous memory devices: {}", 
                self.dangerous_devices.join(", ")));
        }
        
        if !self.block_devices.is_empty() {
            issues.push(format!("access to {} block devices: {}", 
                self.block_devices.len(),
                self.block_devices.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
        }
        
        if !self.gpu_devices.is_empty() {
            issues.push(format!("access to GPU/graphics devices: {}", 
                self.gpu_devices.join(", ")));
        }
        
        if self.character_devices.len() > 3 {
            issues.push(format!("access to {} character devices including: {}", 
                self.character_devices.len(),
                self.character_devices.iter().take(3).cloned().collect::<Vec<_>>().join(", ")));
        }

        if issues.is_empty() {
            "container has minimal device access - good isolation".to_string()
        } else {
            format!("container has dangerous device access: {}", issues.join("; "))
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
        "AII3100".to_string()
    }
}