# SPDX-License-Identifier: GPL-2.0

KDIR ?= /lib/modules/$(shell uname -r)/build
HOST_ARCH := $(shell uname -m)
ARCH ?= $(if $(filter aarch64 arm64,$(HOST_ARCH)),arm64,x86_64)
LLVM ?= 1
KERNEL_RELEASE ?= $(shell $(MAKE) -s -C "$(KDIR)" kernelrelease 2>/dev/null)
TARGET_DIR ?= $(CURDIR)/target/$(ARCH)/$(KERNEL_RELEASE)
RUSTUP_TOOLCHAIN ?=
RUST_MIN_TOOLCHAIN := $(shell [ -x "$(KDIR)/scripts/min-tool-version.sh" ] && "$(KDIR)/scripts/min-tool-version.sh" rustc)
RUST_TOOLCHAIN := $(if $(RUSTUP_TOOLCHAIN),$(RUSTUP_TOOLCHAIN),$(RUST_MIN_TOOLCHAIN))
MODULE_RUSTFLAGS_EXTRA :=
ifneq ($(findstring /usr/src/linux-headers-,$(KDIR)),)
MODULE_RUSTFLAGS_EXTRA += --cfg kernel_module_authors_plural
endif
KBUILD_ENV := $(if $(RUST_TOOLCHAIN),env RUSTUP_TOOLCHAIN=$(RUST_TOOLCHAIN),env)
KBUILD_RUSTFLAGS := $(if $(strip $(MODULE_RUSTFLAGS_EXTRA)),KRUSTFLAGS="$(MODULE_RUSTFLAGS_EXTRA)" RUSTFLAGS_MODULE="$(MODULE_RUSTFLAGS_EXTRA)",)
MODULE_BASENAME := silverseal_rootkit
ARTIFACT_GLOBS := \
	$(MODULE_BASENAME).ko \
	$(MODULE_BASENAME).o \
	$(MODULE_BASENAME).mod \
	$(MODULE_BASENAME).mod.c \
	$(MODULE_BASENAME).mod.o \
	$(MODULE_BASENAME).mod.o.cmd \
	.$(MODULE_BASENAME).o.cmd \
	.$(MODULE_BASENAME).ko.cmd \
	.$(MODULE_BASENAME).mod.cmd \
	.$(MODULE_BASENAME).mod.o.cmd \
	Module.symvers \
	.Module.symvers.cmd \
	modules.order \
	.modules.order.cmd \
	..module-common.o.cmd \
	.module-common.o

define stage_artifacts
	@mkdir -p $(TARGET_DIR)
	@for artifact in $(ARTIFACT_GLOBS); do \
		if [ -e "$(CURDIR)/$$artifact" ]; then \
			mv -f "$(CURDIR)/$$artifact" "$(TARGET_DIR)/"; \
		fi; \
	done
endef

default:
	$(KBUILD_ENV) $(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) LLVM=$(LLVM) $(KBUILD_RUSTFLAGS)
	$(stage_artifacts)

modules_install: default
	$(KBUILD_ENV) $(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) LLVM=$(LLVM) modules_install $(KBUILD_RUSTFLAGS)

clean:
	$(KBUILD_ENV) $(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) LLVM=$(LLVM) clean $(KBUILD_RUSTFLAGS)
	@rm -rf $(TARGET_DIR)
