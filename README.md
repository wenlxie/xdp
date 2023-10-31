# xdp
This is the dispatcher program for XDP, which is used to support multiple XDP programs

clang -O2 -Wall -g -target bpf -c xdpcap.c -o xdpcap.o
clang -O2 -Wall -g -target bpf -c xdp-dispatcher.c -o xdp-dispatcher.o
