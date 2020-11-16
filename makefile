IDIR=./include/

portscanner:
	gcc portscanner.c -o prtsc -lpthread -ggdb -I$(IDIR)