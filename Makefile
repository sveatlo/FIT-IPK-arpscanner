GCC=g++-4.8
FLAGS=-std=c++11 -O0 -g

all: main.cpp arp_scanner utils
	$(GCC) $(FLAGS) main.cpp arp_scanner.o utils.o -o arp-scanner

arp_scanner: ARPScanner.cpp ARPScanner.h
	$(GCC) $(FLAGS) -c ARPScanner.cpp -o arp_scanner.o

utils: Utils.cpp Utils.h
	$(GCC) $(FLAGS) -c Utils.cpp -o utils.o


clean:
	rm -rf arp-scanner *.o
