all: tcp-block.c
	gcc -o tcp-block tcp-block.c -lpcap

clean:
	rm -f tcp-block