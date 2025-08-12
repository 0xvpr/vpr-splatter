EXTRA_CFLAGS := 
obj-m        := splatter.o

CFLAGS       := $(CFLAGS) $(EXTRA_CFLAGS)

all:
	make -C /lib/modules/6.6.87.2-microsoft-standard-WSL2/build M=$(PWD) modules
clean:
	make -C /lib/modules/6.6.87.2-microsoft-standard-WSL2/build M=$(PWD) clean
