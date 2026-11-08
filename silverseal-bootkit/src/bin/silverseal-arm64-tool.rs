//! Creates a fail-closed ARM64 target profile for one exact stock boot chain.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use silverseal_bootkit::arm64_profile::Arm64Profile;

const PROFILE_KEYS: &[&str] = &[
    "grub-signature",
    "zboot-signature",
    "initcall-signature",
    "code-cave-signature",
    "schedule-work-signature",
    "initcall-entry-offset",
    "code-cave-offset",
    "code-cave-capacity",
    "data-cave-capacity",
    "kernel-image-len",
    "initcall-entry-virtual",
    "code-cave-virtual",
    "data-cave-virtual",
    "schedule-work-virtual",
    "msleep-virtual",
    "call-usermodehelper-virtual",
    "module-path",
    "output",
];

fn main() {
    if let Err(error) = run(env::args_os().skip(1).collect()) {
        eprintln!("error: {error}");
        eprintln!();
        print_usage();
        std::process::exit(2);
    }
}

fn run(args: Vec<OsString>) -> Result<(), String> {
    let Some(command) = args.first().and_then(|arg| arg.to_str()) else {
        return Err("missing command".into());
    };
    match command {
        "profile" => create_profile(parse_options(&args[1..], PROFILE_KEYS)?),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => Err(format!("unknown command '{command}'")),
    }
}

fn create_profile(options: BTreeMap<String, OsString>) -> Result<(), String> {
    let grub_signature = read_nonempty(option_path(&options, "grub-signature")?)?;
    let zboot_signature = read_nonempty(option_path(&options, "zboot-signature")?)?;
    let initcall_signature = read_nonempty(option_path(&options, "initcall-signature")?)?;
    let code_cave_signature = read_nonempty(option_path(&options, "code-cave-signature")?)?;
    let schedule_work_signature = read_nonempty(option_path(&options, "schedule-work-signature")?)?;
    let module_path = option_text(&options, "module-path")?;
    let profile = Arm64Profile {
        grub_signature: &grub_signature,
        zboot_signature: &zboot_signature,
        initcall_signature: &initcall_signature,
        code_cave_signature: &code_cave_signature,
        schedule_work_signature: &schedule_work_signature,
        initcall_entry_offset: option_usize(&options, "initcall-entry-offset")?,
        code_cave_offset: option_usize(&options, "code-cave-offset")?,
        code_cave_capacity: option_usize(&options, "code-cave-capacity")?,
        data_cave_capacity: option_usize(&options, "data-cave-capacity")?,
        kernel_image_len: option_usize(&options, "kernel-image-len")?,
        initcall_entry_virtual: option_usize(&options, "initcall-entry-virtual")?,
        code_cave_virtual: option_usize(&options, "code-cave-virtual")?,
        data_cave_virtual: option_usize(&options, "data-cave-virtual")?,
        schedule_work_virtual: option_usize(&options, "schedule-work-virtual")?,
        msleep_virtual: option_usize(&options, "msleep-virtual")?,
        call_usermodehelper_virtual: option_usize(&options, "call-usermodehelper-virtual")?,
        module_path: module_path.as_bytes(),
    };
    let mut encoded = vec![0; profile.encoded_len().map_err(debug_error)?];
    profile.encode_into(&mut encoded).map_err(debug_error)?;
    write_new(option_path(&options, "output")?, &encoded)
}

fn parse_options(
    args: &[OsString],
    allowed: &[&str],
) -> Result<BTreeMap<String, OsString>, String> {
    if !args.len().is_multiple_of(2) {
        return Err("every option requires a value".into());
    }
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    let mut options = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        let key = pair[0]
            .to_str()
            .and_then(|value| value.strip_prefix("--"))
            .ok_or_else(|| "options must use --name value syntax".to_string())?;
        if !allowed.contains(key) {
            return Err(format!("unknown option '--{key}'"));
        }
        if options.insert(key.to_string(), pair[1].clone()).is_some() {
            return Err(format!("duplicate option '--{key}'"));
        }
    }
    for key in allowed {
        if !options.contains_key(key) {
            return Err(format!("missing required option '--{key}'"));
        }
    }
    Ok(options)
}

fn option_path<'a>(options: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a Path, String> {
    options
        .get(key)
        .map(Path::new)
        .ok_or_else(|| format!("missing required option '--{key}'"))
}

fn option_text<'a>(options: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    options
        .get(key)
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("--{key} must be valid Unicode"))
}

fn option_usize(options: &BTreeMap<String, OsString>, key: &str) -> Result<usize, String> {
    parse_usize(option_text(options, key)?).map_err(|error| format!("--{key}: {error}"))
}

fn parse_usize(value: &str) -> Result<usize, String> {
    let (radix, digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((10, value), |digits| (16, digits));
    if digits.is_empty() {
        return Err("empty integer".into());
    }
    usize::from_str_radix(digits, radix).map_err(|_| format!("invalid integer '{value}'"))
}

fn read_nonempty(path: &Path) -> Result<Vec<u8>, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| write_error(path, error))?;
    file.write_all(bytes)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn write_error(path: &Path, error: io::Error) -> String {
    if error.kind() == io::ErrorKind::AlreadyExists {
        format!("refusing to overwrite existing output {}", path.display())
    } else {
        format!("failed to create {}: {error}", path.display())
    }
}

fn debug_error(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

fn print_usage() {
    eprintln!(
        "silverseal-arm64-tool profile \\\n+  --grub-signature FILE --zboot-signature FILE --initcall-signature FILE \\\n+  --code-cave-signature FILE --schedule-work-signature FILE \\\n+  --initcall-entry-offset N --code-cave-offset N \\\n+  --code-cave-capacity N --data-cave-capacity N --kernel-image-len N \\\n+  --initcall-entry-virtual N --code-cave-virtual N --data-cave-virtual N \\\n+  --schedule-work-virtual N --msleep-virtual N --call-usermodehelper-virtual N \\\n+  --module-path /silverseal_rootkit.ko --output FILE"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_decimal_and_hexadecimal_integers() {
        assert_eq!(parse_usize("42"), Ok(42));
        assert_eq!(parse_usize("0x2a"), Ok(42));
        assert!(parse_usize("0x").is_err());
        assert!(parse_usize("nope").is_err());
    }

    #[test]
    fn rejects_unknown_duplicate_and_missing_options() {
        let pair = |key: &str, value: &str| [OsString::from(key), OsString::from(value)];
        assert!(parse_options(&pair("--bad", "x"), &["good"]).is_err());
        let duplicate = [pair("--good", "x"), pair("--good", "y")].concat();
        assert!(parse_options(&duplicate, &["good"]).is_err());
        assert!(parse_options(&[], &["good"]).is_err());
    }

    #[test]
    fn creates_parseable_v3_profile_and_refuses_overwrite() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "silverseal-arm64-tool-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();

        let signatures = [
            ("grub-signature", "grub.sig", 0x11, 32),
            ("zboot-signature", "zboot.sig", 0x22, 52),
            ("initcall-signature", "initcall.sig", 0x33, 32),
            ("code-cave-signature", "code-cave.sig", 0x44, 32),
            ("schedule-work-signature", "schedule.sig", 0x55, 32),
        ];
        let mut options = BTreeMap::new();
        for (key, name, byte, len) in signatures {
            let path = root.join(name);
            fs::write(&path, vec![byte; len]).unwrap();
            options.insert(key.to_string(), path.into_os_string());
        }
        let output = root.join("fixture.ssarm64p");
        for (key, value) in [
            ("initcall-entry-offset", "24"),
            ("code-cave-offset", "32"),
            ("code-cave-capacity", "256"),
            ("data-cave-capacity", "2040"),
            ("kernel-image-len", "0x4540000"),
            ("initcall-entry-virtual", "0xffff8000831ce498"),
            ("code-cave-virtual", "0xffff800080010b84"),
            ("data-cave-virtual", "0xffff8000843e6808"),
            ("schedule-work-virtual", "0xffff80008003d578"),
            ("msleep-virtual", "0xffff8000802981b0"),
            ("call-usermodehelper-virtual", "0xffff80008015e2f0"),
            ("module-path", "/silverseal_rootkit.ko"),
        ] {
            options.insert(key.to_string(), value.into());
        }
        options.insert("output".into(), output.clone().into_os_string());

        create_profile(options.clone()).unwrap();
        let bytes = fs::read(&output).unwrap();
        let profile = Arm64Profile::parse(&bytes).unwrap();
        assert_eq!(profile.schedule_work_virtual, 0xffff80008003d578);
        assert_eq!(profile.module_path, b"/silverseal_rootkit.ko");
        assert!(create_profile(options).unwrap_err().contains("overwrite"));

        fs::remove_dir_all(root).unwrap();
    }
}
