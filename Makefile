CLANG = clang
CFLAGS = -O2 -target bpf -I/usr/include/x86_64-linux-gnu

all: bpf go

bpf:
	$(CLANG) $(CFLAGS) -c bpf/core.c -o bpf/core.o

go:
	go build -o dashboard cmd/dashboard/main.go
	go build -o ctrl cmd/ctrl/main.go

clean:
	rm -f bpf/*.o
	rm -f dashboard ctrl
