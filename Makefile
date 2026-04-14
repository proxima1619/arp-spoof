all:
	g++ -std=c++11 -Wall -Wextra -O2 -c arphdr.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -c ethhdr.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -c ip.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -c mac.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -c arp-spoof.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -o arp-spoof arphdr.o ethhdr.o ip.o mac.o arp-spoof.o -lpcap

clean:
	rm -f *.o arp-spoof
