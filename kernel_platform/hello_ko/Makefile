obj-m += Shanzi.o

KDIR ?= /home/shanzi/kernel_workspace/kernel_platform/common/out
PWD := $(CURDIR)
ARCH ?= arm64
LLVM ?= /home/shanzi/kernel_workspace/kernel_platform/prebuilts/clang/host/linux-x86/clang-r510928/bin/
PAHOLE ?= /home/shanzi/kernel_workspace/kernel_platform/prebuilts/kernel-build-tools/linux-x86/bin/pahole
CC := clang

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) LLVM=$(LLVM) CC=$(CC) PAHOLE=$(PAHOLE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) LLVM=$(LLVM) CC=$(CC) PAHOLE=$(PAHOLE) clean
