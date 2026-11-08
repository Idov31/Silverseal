use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const PROFILE_ENV: &str = "SILVERSEAL_ARM64_PROFILE";
const EMBEDDED_PROFILE_NAME: &str = "embedded-arm64-profile.bin";

fn main() {
    println!("cargo:rerun-if-env-changed={PROFILE_ENV}");
    println!("cargo:rustc-check-cfg=cfg(silverseal_embedded_arm64_profile)");
    stage_optional_file(
        PROFILE_ENV,
        EMBEDDED_PROFILE_NAME,
        "silverseal_embedded_arm64_profile",
    );

    let target_arch =
        env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo did not set CARGO_CFG_TARGET_ARCH");

    match target_arch.as_str() {
        "x86_64" => build_x86_64_blobs(),
        "aarch64" => {
            // ARM64 code is assembled by the Rust compiler through global_asm.
            // Do not try to assemble the x64 NASM files for this target.
            println!("cargo:rerun-if-changed=asm/arm");
        }
        other => panic!("unsupported bootkit target architecture: {other}"),
    }
}

fn stage_optional_file(env_name: &str, output_name: &str, cfg_name: &str) {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let destination = out_dir.join(output_name);

    match env::var_os(env_name) {
        Some(source) => {
            let source = PathBuf::from(source);
            let metadata = fs::metadata(&source).unwrap_or_else(|error| {
                panic!("failed to inspect {env_name}={}: {error}", source.display())
            });
            assert!(
                metadata.is_file() && metadata.len() > 0,
                "{env_name} must name a non-empty file"
            );
            println!("cargo:rerun-if-changed={}", source.display());
            fs::copy(&source, &destination).unwrap_or_else(|error| {
                panic!(
                    "failed to stage {} as {}: {error}",
                    source.display(),
                    destination.display()
                )
            });
            println!("cargo:rustc-cfg={cfg_name}");
        }
        None => {
            fs::write(&destination, []).unwrap_or_else(|error| {
                panic!(
                    "failed to create placeholder {}: {error}",
                    destination.display()
                )
            });
        }
    }
}

fn build_x86_64_blobs() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let loader_output = assemble_blob(&out_dir, "asm/x64/lkm_loader.asm", "lkm_loader.bin");
    println!("cargo:rustc-env=LKM_LOADER_BIN={}", loader_output.display());

    // Assemble the initcall stager blob.
    let stager_output = assemble_blob(&out_dir, "asm/x64/lkm_stager.asm", "lkm_stager.bin");
    println!("cargo:rustc-env=LKM_STAGER_BIN={}", stager_output.display());

    // Assemble the split worker blobs.
    let worker_output = assemble_blob(&out_dir, "asm/x64/lkm_worker.asm", "lkm_worker.bin");
    println!("cargo:rustc-env=LKM_WORKER_BIN={}", worker_output.display());

    let worker_tail_output = assemble_blob(
        &out_dir,
        "asm/x64/lkm_worker_tail.asm",
        "lkm_worker_tail.bin",
    );
    println!(
        "cargo:rustc-env=LKM_WORKER_TAIL_BIN={}",
        worker_tail_output.display()
    );
}

fn assemble_blob(out_dir: &Path, source: &str, output_name: &str) -> PathBuf {
    let asm_source = PathBuf::from(source);
    let bin_output = out_dir.join(output_name);

    println!("cargo:rerun-if-changed={}", asm_source.display());

    let status = Command::new("nasm")
        .arg("-f")
        .arg("bin")
        .arg("-o")
        .arg(&bin_output)
        .arg(&asm_source)
        .status()
        .expect("Failed to run nasm. Is it installed?");

    if !status.success() {
        panic!("nasm failed to assemble {}", asm_source.display());
    }

    bin_output
}
