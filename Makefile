obj-m += Shanzi.o

ccflags-y += -DSHANZI_RELEASE_BUILD
ccflags-y += -fno-ident
ccflags-y += -fno-asynchronous-unwind-tables
ccflags-y += -fno-unwind-tables
ccflags-y += -fmerge-all-constants
ccflags-y += -fdata-sections
ccflags-y += -ffunction-sections

KDIR ?= /home/shanzi/kernel_workspace/kernel_platform/common/out
PWD := $(CURDIR)
ARCH ?= arm64
LLVM ?= /home/shanzi/kernel_workspace/kernel_platform/prebuilts/clang/host/linux-x86/clang-r510928/bin/
PAHOLE ?= /home/shanzi/kernel_workspace/kernel_platform/prebuilts/kernel-build-tools/linux-x86/bin/pahole
STRIP ?= llvm-strip

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) LLVM=$(LLVM) PAHOLE=$(PAHOLE) modules
	$(STRIP) --strip-debug $(PWD)/Shanzi.ko || true

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) LLVM=$(LLVM) PAHOLE=$(PAHOLE) clean
