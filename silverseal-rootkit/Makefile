# SPDX-License-Identifier: GPL-2.0

KDIR ?= /lib/modules/$(shell uname -r)/build
RUST_MIN_TOOLCHAIN := $(shell [ -x "$(KDIR)/scripts/min-tool-version.sh" ] && "$(KDIR)/scripts/min-tool-version.sh" rustc)
KBUILD_ENV := $(if $(RUST_MIN_TOOLCHAIN),env RUSTUP_TOOLCHAIN=$(RUST_MIN_TOOLCHAIN),env)

default:
	$(KBUILD_ENV) $(MAKE) -C $(KDIR) M=$(PWD) LLVM=1

modules_install: default
	$(KBUILD_ENV) $(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(KBUILD_ENV) $(MAKE) -C $(KDIR) M=$(PWD) clean
