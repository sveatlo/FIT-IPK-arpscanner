GCC=g++-4.8
FLAGS=-pthread -lpthread -Wl,--no-as-needed -std=c++11 -O0 -g -rdynamic

all: main.cpp arpscanner utils interface ipv4 ipv6
	$(GCC) $(FLAGS) main.cpp arpscanner.o utils.o interface.o ipv4.o ipv6.o -o arp-scanner

arpscanner: ARPScanner.cpp ARPScanner.h
	$(GCC) $(FLAGS) -c ARPScanner.cpp -o arpscanner.o

utils: Utils.cpp Utils.h
	$(GCC) $(FLAGS) -c Utils.cpp -o utils.o

interface: Interface.cpp Interface.h
	$(GCC) $(FLAGS) -c Interface.cpp -o interface.o

ipv4: IPv4.cpp IPv4.h
	$(GCC) $(FLAGS) -c IPv4.cpp -o ipv4.o

ipv6: IPv6.cpp IPv6.h
	$(GCC) $(FLAGS) -c IPv6.cpp -o ipv6.o


clean:
	rm -rf arp-scanner *.o *.h.gch *.xml

pack:
	tar czf xhanze10.tar.gz *.h *.cpp Makefile documentation/ARP_scanner-documentation.pdf
