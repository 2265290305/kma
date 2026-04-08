obj-m += Shanzi.o

ccflags-y += -DSHANZI_RELEASE_BUILD
ccflags-y += -fno-ident
ccflags-y += -fno-asynchronous-unwind-tables
ccflags-y += -fno-unwind-tables
ccflags-y += -fmerge-all-constants
ccflags-y += -fdata-sections
ccflags-y += -ffunction-sections
ccflags-y += -Wno-unknown-attributes

KDIR ?= /home/shanzi/kernel_workspace/kernel_platform/common/out
PWD := $(CURDIR)
ARCH ?= arm64
CLANG_VERSION ?= r510928
CLANG_BIN ?= /home/shanzi/kernel_workspace/kernel_platform/prebuilts/clang/host/linux-x86/clang-$(CLANG_VERSION)/bin
PAHOLE ?= /home/shanzi/kernel_workspace/kernel_platform/prebuilts/kernel-build-tools/linux-x86/bin/pahole
STRIP ?= llvm-strip

all:
	PATH=$(CLANG_BIN):$$PATH $(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) LLVM=1 CC=clang HOSTCC=clang LD=ld.lld HOSTLD=ld.lld PAHOLE=$(PAHOLE) modules
	$(STRIP) --strip-debug $(PWD)/Shanzi.ko || true

clean:
	PATH=$(CLANG_BIN):$$PATH $(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) LLVM=1 CC=clang HOSTCC=clang LD=ld.lld HOSTLD=ld.lld PAHOLE=$(PAHOLE) clean
