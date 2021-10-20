CC=clang
LIBS=-lelf -lbpf

all: xdp_loader xdp_program.o

xdp_program.o: xdp_program.c
	$(CC) -target bpf -O2 -c xdp_program.c -o xdp_program.o
	
xdp_loader.o: xdp_loader.c
	$(CC) -c xdp_loader.c -o xdp_loader.o

xdp_loader: xdp_loader.o
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm *.o xdp_loader
