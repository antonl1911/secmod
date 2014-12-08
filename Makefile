secmod-objs :=  seccon.o probe.o
obj-m += secmod.o

KBUILD_CFLAGS += -w

all:
		make -w -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
		$(CC) seccon_user.c -o seccon_user
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


