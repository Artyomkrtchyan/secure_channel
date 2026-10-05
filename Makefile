CC = gcc
CFLAGS = -Wall -O2

all: device sender receiver

device: device.c
	$(CC) $(CFLAGS) -o device device.c -lcrypto

sender: sender.c
	$(CC) $(CFLAGS) -o sender sender.c

receiver: receiver.c
	$(CC) $(CFLAGS) -o receiver receiver.c

clean:
	rm -f device sender receiver
