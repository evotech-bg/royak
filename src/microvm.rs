#![allow(dead_code)]
//! MicroVM — lightweight Linux VM for macOS using Apple Virtualization.framework
//!
//! When NeuroPod runs on macOS, Linux binaries can't execute natively.
//! Instead of Docker Desktop (2-4GB RAM, 30s boot), we boot a micro Linux VM:
//!   - 64MB RAM, 2 vCPU
//!   - Alpine Linux kernel (~5MB) + initramfs (~10MB)
//!   - Boot: <2 seconds
//!   - Shared filesystem via virtio-fs (NeuroPod rootfs)
//!   - NAT networking (port forwarding)
//!
//! The VM launcher is a Swift program using Apple's Virtualization.framework,
//! compiled on first use and cached. Most items below are staged for the
//! end-to-end macOS NeuroPod path and not yet reached from main().

use std::path::{Path, PathBuf};

const VM_DIR: &str = ".royak/vm";
const SWIFT_LAUNCHER: &str = "neuropod-vm";

/// MicroVM instance
pub struct MicroVM {
    pub vm_dir: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub shared_dir: PathBuf,  // NeuroPod rootfs mounted via virtio-fs
    pub disk_img: PathBuf,    // data disk passed via virtio-blk
    pub pid: Option<u32>,
    pub ram_mb: u64,
    pub cpus: u32,
}

impl MicroVM {
    /// Check if MicroVM is available on this system
    pub fn is_available() -> bool {
        #[cfg(target_os = "macos")]
        {
            // Check macOS 12+ and swiftc available
            let os_ok = std::process::Command::new("sw_vers")
                .args(["-productVersion"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|v| v.trim().split('.').next()?.parse::<u32>().ok())
                .map(|major| major >= 12)
                .unwrap_or(false);

            let swift_ok = std::process::Command::new("swiftc")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            os_ok && swift_ok
        }
        #[cfg(not(target_os = "macos"))]
        { false }
    }

    /// Prepare the MicroVM (download kernel, compile launcher)
    pub fn prepare(shared_dir: &Path, disk_img: &Path, ram_mb: u64, cpus: u32) -> Result<Self, String> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let vm_dir = PathBuf::from(&home).join(VM_DIR);
        std::fs::create_dir_all(&vm_dir).map_err(|e| format!("mkdir vm: {e}"))?;

        let kernel = vm_dir.join("vmlinuz");
        let initrd = vm_dir.join("initramfs");
        let launcher = vm_dir.join(SWIFT_LAUNCHER);

        // Download Alpine Linux kernel + initramfs if not cached
        if !kernel.exists() || !initrd.exists() {
            eprintln!("  [microvm] downloading Alpine Linux kernel...");
            download_kernel(&vm_dir)?;
        }

        // Compile Swift VM launcher if not cached
        if !launcher.exists() {
            eprintln!("  [microvm] compiling VM launcher...");
            compile_launcher(&vm_dir)?;
        }

        Ok(MicroVM {
            vm_dir,
            kernel,
            initrd,
            shared_dir: shared_dir.to_path_buf(),
            disk_img: disk_img.to_path_buf(),
            pid: None,
            ram_mb,
            cpus,
        })
    }

    /// Boot the MicroVM
    pub fn boot(&mut self) -> Result<u32, String> {
        let launcher = self.vm_dir.join(SWIFT_LAUNCHER);
        if !launcher.exists() {
            return Err("VM launcher not compiled".to_string());
        }

        let child = std::process::Command::new(&launcher)
            .args([
                "--kernel", self.kernel.to_str().unwrap_or(""),
                "--initrd", self.initrd.to_str().unwrap_or(""),
                "--shared", self.shared_dir.to_str().unwrap_or(""),
                "--disk", self.disk_img.to_str().unwrap_or(""),
                "--ram", &self.ram_mb.to_string(),
                "--cpus", &self.cpus.to_string(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("boot: {e}"))?;

        let pid = child.id();
        self.pid = Some(pid);
        eprintln!("  [microvm] booted (pid={pid}, ram={}MB, cpus={})", self.ram_mb, self.cpus);
        Ok(pid)
    }

    /// Shutdown the MicroVM
    pub fn shutdown(&mut self) {
        if let Some(pid) = self.pid.take() {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
                std::thread::sleep(std::time::Duration::from_secs(2));
                libc::kill(pid as i32, libc::SIGKILL);
            }
            eprintln!("  [microvm] shutdown (pid={pid})");
        }
    }

    /// Get VM status
    pub fn is_running(&self) -> bool {
        self.pid.map(|p| unsafe { libc::kill(p as i32, 0) == 0 }).unwrap_or(false)
    }
}

/// Download Alpine Linux kernel + initramfs for ARM64
fn download_kernel(vm_dir: &Path) -> Result<(), String> {
    let arch = std::env::consts::ARCH;
    let alpine_arch = match arch {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        a => return Err(format!("unsupported arch: {a}")),
    };

    // Alpine Linux netboot — official, stable, minimal
    let base = format!("https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/{alpine_arch}/netboot");
    let kernel_url = format!("{base}/vmlinuz-lts");
    let initrd_url = format!("{base}/initramfs-lts");

    let kernel_path = vm_dir.join("vmlinuz");
    let initrd_path = vm_dir.join("initramfs");

    download_file(&kernel_url, &kernel_path)?;
    download_file(&initrd_url, &initrd_path)?;

    eprintln!("  [microvm] kernel: {} ({} bytes)",
        kernel_path.display(),
        std::fs::metadata(&kernel_path).map(|m| m.len()).unwrap_or(0));

    Ok(())
}

fn download_file(url: &str, dest: &Path) -> Result<(), String> {
    let dest_str = dest.to_str().unwrap_or("output");
    let output = std::process::Command::new("curl")
        .args(["-sL", "-o", dest_str, url])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !output.status.success() {
        return Err(format!("download failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    Ok(())
}

/// Compile the Swift VM launcher using Apple Virtualization.framework
fn compile_launcher(vm_dir: &Path) -> Result<(), String> {
    let swift_code = generate_swift_launcher();
    let swift_path = vm_dir.join("launcher.swift");
    let binary_path = vm_dir.join(SWIFT_LAUNCHER);

    std::fs::write(&swift_path, &swift_code).map_err(|e| format!("write swift: {e}"))?;

    let output = std::process::Command::new("swiftc")
        .args([
            "-O",
            "-o", binary_path.to_str().unwrap_or(""),
            swift_path.to_str().unwrap_or(""),
            "-framework", "Virtualization",
        ])
        .output()
        .map_err(|e| format!("swiftc: {e}"))?;

    if !output.status.success() {
        return Err(format!("compile failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    eprintln!("  [microvm] launcher compiled: {}", binary_path.display());
    Ok(())
}

/// Generate the Swift code for the VM launcher
fn generate_swift_launcher() -> String {
    r#"
import Foundation
import Virtualization

// Parse arguments
var kernel = "", initrd = "", shared = "", disk = ""
var ram: UInt64 = 64, cpus: Int = 2

var args = CommandLine.arguments.dropFirst().makeIterator()
while let arg = args.next() {
    switch arg {
    case "--kernel": kernel = args.next() ?? ""
    case "--initrd": initrd = args.next() ?? ""
    case "--shared": shared = args.next() ?? ""
    case "--disk":   disk = args.next() ?? ""
    case "--ram":    ram = UInt64(args.next() ?? "64") ?? 64
    case "--cpus":   cpus = Int(args.next() ?? "2") ?? 2
    default: break
    }
}

guard !kernel.isEmpty else {
    fputs("Usage: neuropod-vm --kernel <path> --initrd <path> --shared <dir> --disk <img>\n", stderr)
    exit(1)
}

// VM Configuration
let config = VZVirtualMachineConfiguration()
config.cpuCount = cpus
config.memorySize = ram * 1024 * 1024

// Linux boot loader
let bootLoader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: kernel))
if !initrd.isEmpty {
    bootLoader.initialRamdiskURL = URL(fileURLWithPath: initrd)
}
bootLoader.commandLine = "console=hvc0 root=/dev/vda rw quiet"
config.bootLoader = bootLoader

// Serial console → stdout
let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
serial.attachment = VZFileHandleSerialPortAttachment(
    fileHandleForReading: FileHandle.standardInput,
    fileHandleForWriting: FileHandle.standardOutput
)
config.serialPorts = [serial]

// Shared directory (NeuroPod rootfs via virtio-fs)
if !shared.isEmpty {
    let sharedConfig = VZVirtioFileSystemDeviceConfiguration(tag: "neuropod")
    sharedConfig.share = VZSingleDirectoryShare(
        directory: VZSharedDirectory(url: URL(fileURLWithPath: shared), readOnly: false)
    )
    config.directorySharingDevices = [sharedConfig]
}

// Data disk (sparse image via virtio-blk)
if !disk.isEmpty, FileManager.default.fileExists(atPath: disk) {
    if let attachment = try? VZDiskImageStorageDeviceAttachment(
        url: URL(fileURLWithPath: disk), readOnly: false
    ) {
        config.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: attachment)]
    }
}

// Network (NAT — internet access + port forwarding)
let network = VZVirtioNetworkDeviceConfiguration()
network.attachment = VZNATNetworkDeviceAttachment()
config.networkDevices = [network]

// Entropy (for /dev/urandom inside VM)
config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

// Validate and boot
do {
    try config.validate()
} catch {
    fputs("VM config invalid: \(error)\n", stderr)
    exit(1)
}

let vm = VZVirtualMachine(configuration: config)

fputs("[microvm] booting Linux...\n", stderr)

vm.start { result in
    switch result {
    case .success:
        fputs("[microvm] VM running (ram=\(ram)MB, cpus=\(cpus))\n", stderr)
    case .failure(let error):
        fputs("[microvm] boot failed: \(error)\n", stderr)
        exit(1)
    }
}

// Handle SIGTERM for graceful shutdown
signal(SIGTERM) { _ in
    fputs("\n[microvm] shutting down...\n", stderr)
    exit(0)
}

// Keep running until killed
RunLoop.main.run()
"#.to_string()
}
