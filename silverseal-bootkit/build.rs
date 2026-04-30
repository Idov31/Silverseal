use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
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

fn assemble_blob(out_dir: &PathBuf, source: &str, output_name: &str) -> PathBuf {
    let asm_source = PathBuf::from(source);
    let bin_output = out_dir.join(output_name);

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

    bin_output
}
