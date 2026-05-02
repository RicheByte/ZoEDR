# Makefile for ZoEDR Kernel Module

obj-m += zoedr_kernel.o
zoedr_kernel-y := src/zoedr_kernel.o

# KDIR points to the kernel build directory
# $(shell uname -r) gets the current kernel version
KDIR ?= /lib/modules/$(shell uname -r)/build

# Define the source directory relative to the Makefile
SRCDIR := src

# The 'all' target builds the kernel module
all:
	$(MAKE) -C $(KDIR) M=$(PWD) CFLAGS_MODULE="-I$(PWD)/$(SRCDIR)" modules

# The 'clean' target removes build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f src/zoedr_kernel.o zoedr_kernel.o zoedr_kernel.ko

