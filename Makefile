CXX = g++
CXXFLAGS = -std=c++17 -g
LDFLAGS = -lpcap

all: ipk-sniffer

ipk-sniffer: ipk-sniffer.o
	$(CXX) $(LDFLAGS) $^ -o $@
	
clean:
	rm -f *.o ipk-sniffer
