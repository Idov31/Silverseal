// SPDX-License-Identifier: GPL-2.0

//! Silverseal rootkit.
//!
//! Build with:
//!   make KDIR=/lib/modules/$(uname -r)/build M=$PWD LLVM=1
//! Load with:
//!   sudo insmod silverseal_rootkit.ko
//! Verify:
//!   dmesg | tail

use kernel::prelude::*;

module! {
    type: SilversealRootkit,
    name: "silverseal_rootkit",
    authors: ["Ido Veltzman <idov3110@gmail.com>"],
    description: "Silverseal rootkit LKM skeleton",
    license: "GPL",
}

struct SilversealRootkit;

impl kernel::Module for SilversealRootkit {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Hello kernel!\n");
        Ok(Self)
    }
}

impl Drop for SilversealRootkit {
    fn drop(&mut self) {
        pr_info!("Goodbye kernel!\n");
    }
}
