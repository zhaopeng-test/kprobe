
obj-m :=kprobe_ovs.o
KERNEL :=/usr/src/kernels/3.10.0-1160.el7.x86_64/
CURRENT_PATH :=$(shell pwd)

all :
	make -C $(KERNEL) M=$(CURRENT_PATH) modules

.PHONEY:clean

clean :
	rm -f *.o *.ko


