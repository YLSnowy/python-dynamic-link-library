obj-m+=test.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean:
	rm -rf .test.* *odules*