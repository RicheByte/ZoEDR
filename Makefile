# Makefile for ZoEDR Kernel Module
# Assumes the source file is src/zoedr_kernel.c

obj-m += zoedr_kernel.o

# KDIR points to the kernel build directory
# $(shell uname -r) gets the current kernel version
KDIR := /lib/modules/$(shell uname -r)/build

# Define the source directory relative to the Makefile
SRCDIR := src

# The 'all' target builds the kernel module
all:
	$(MAKE) -C $(KDIR) M=$(PWD) CFLAGS="-I$(PWD)/$(SRCDIR)" modules

# The 'clean' target removes build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f zoedr_kernel.o
