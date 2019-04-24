all: proman-nand

proman-nand: proman-nand.c
	gcc -O0 -g3 -o proman-nand proman-nand.c -I/usr/local/include -L. -lm -lc -L/usr/local/lib -lusb-1.0

clean:
	rm -f *.o proman-nand

install:
	cp 20-proman.rules /etc/udev/rules.d/
