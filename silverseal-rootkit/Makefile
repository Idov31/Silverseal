# SPDX-License-Identifier: GPL-2.0

KDIR ?= /lib/modules/$(shell uname -r)/build
TARGET_DIR ?= $(PWD)/target
RUST_MIN_TOOLCHAIN := $(shell [ -x "$(KDIR)/scripts/min-tool-version.sh" ] && "$(KDIR)/scripts/min-tool-version.sh" rustc)
KBUILD_ENV := $(if $(RUST_MIN_TOOLCHAIN),env RUSTUP_TOOLCHAIN=$(RUST_MIN_TOOLCHAIN),env)
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
	.modules.order.cmd

define stage_artifacts
	@mkdir -p $(TARGET_DIR)
	@for artifact in $(ARTIFACT_GLOBS); do \
		if [ -e "$(PWD)/$$artifact" ]; then \
			mv -f "$(PWD)/$$artifact" "$(TARGET_DIR)/"; \
		fi; \
	done
endef

default:
	$(KBUILD_ENV) $(MAKE) -C $(KDIR) M=$(PWD) LLVM=1
	$(stage_artifacts)

modules_install: default
	$(KBUILD_ENV) $(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(KBUILD_ENV) $(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -rf $(TARGET_DIR)
