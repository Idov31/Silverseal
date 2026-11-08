#[cfg(target_arch = "aarch64")]
pub mod arm64_hooks;
#[cfg(target_arch = "aarch64")]
pub mod arm64_injection;
#[cfg(target_arch = "x86_64")]
pub mod boot_hooks;
#[cfg(target_arch = "x86_64")]
pub mod kernel_hooks;
