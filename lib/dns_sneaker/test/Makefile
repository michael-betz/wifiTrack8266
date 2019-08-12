# For compiling test.c on linux
# to compare numbers against the pyhton notebook
LIB_AES_DIR = ../../../.pio/libdeps/nodemcu/tiny-AES-c_ID5421
vpath %.c $(LIB_AES_DIR)
vpath %.c ../src

OBJS = aes.o dns_sneaker.o

CFLAGS += -I../src -I$(LIB_AES_DIR) -g -DTEST

test: $(OBJS)

clean:
	rm -f $(OBJS) aes.o test
