use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let asm_source = PathBuf::from("asm/x64/lkm_loader.asm");
    let bin_output = out_dir.join("lkm_loader.bin");

    println!("cargo:rerun-if-changed={}", asm_source.display());

    let status = Command::new("nasm")
        .args([
            "-f",
            "bin",
            "-o",
            bin_output.to_str().unwrap(),
            asm_source.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to run nasm. Is it installed?");

    if !status.success() {
        panic!("nasm failed to assemble {}", asm_source.display());
    }

    println!("cargo:rustc-env=LKM_LOADER_BIN={}", bin_output.display());

    // Assemble the 29-byte stager blob.
    let stager_source = PathBuf::from("asm/x64/lkm_stager.asm");
    let stager_output = out_dir.join("lkm_stager.bin");

    println!("cargo:rerun-if-changed={}", stager_source.display());

    let status = Command::new("nasm")
        .args([
            "-f",
            "bin",
            "-o",
            stager_output.to_str().unwrap(),
            stager_source.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to run nasm. Is it installed?");

    if !status.success() {
        panic!("nasm failed to assemble {}", stager_source.display());
    }

    println!("cargo:rustc-env=LKM_STAGER_BIN={}", stager_output.display());

    // Assemble the 29-byte worker_resume blob.
    let worker_resume_source = PathBuf::from("asm/x64/lkm_worker_resume.asm");
    let worker_resume_output = out_dir.join("lkm_worker_resume.bin");

    println!("cargo:rerun-if-changed={}", worker_resume_source.display());

    let status = Command::new("nasm")
        .args([
            "-f",
            "bin",
            "-o",
            worker_resume_output.to_str().unwrap(),
            worker_resume_source.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to run nasm. Is it installed?");

    if !status.success() {
        panic!("nasm failed to assemble {}", worker_resume_source.display());
    }

    println!(
        "cargo:rustc-env=LKM_WORKER_RESUME_BIN={}",
        worker_resume_output.display()
    );
}
