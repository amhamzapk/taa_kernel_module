obj-m += taa.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

debug:
	KCPPFLAGS="-DDEBUG_PRINTS" make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
