/*
 * IPK projekt 2
 * packet sniffer
 * Author: Ondrej Mach (xmacho12)
 *
 * Code snippets from:
 * https://www.tcpdump.org/pcap.html
 *
 */

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <ctime>
#include <cctype>

#include <getopt.h>
#include <pcap.h>

using std::cout;
using std::cerr;

using std::endl;
using std::string;
using std::stoi;

enum Protocol {TCP, UDP, ARP, ICMP, N_PROTOCOLS};

struct Params {
    int filters[N_PROTOCOLS];
    unsigned port;
    unsigned n;
    string interface;
};

static Params params = {0};


void usage(char *name) {
    cerr << "Usage: "
    << name << " [-i rozhraní | --interface rozhraní]"
    << "{-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}"
    << endl;
}

void listInterfaces() {
    // Pointer to the list of all devices
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE+1];

    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        // Devices were read successfully
        // Go through the list of devices and print each one
        pcap_if_t *device = alldevs;

        while (device) {
            cout << device->name << endl;
            device = device->next;
        }

        pcap_freealldevs(alldevs);

    } else {
        // Devices could not be read
        cerr << "Could not read available devices." << endl;
    }
};


void parseParams(int argc, char **argv) {

    static struct option long_options[] = {
        {"tcp", no_argument, &params.filters[TCP], 1},
        {"udp", no_argument, &params.filters[UDP], 1},
        {"arp", no_argument, &params.filters[ARP], 1},
        {"icmp", no_argument, &params.filters[ICMP], 1},
        {"interface", required_argument, 0, 'i'},
        {"port",      required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

    // Capture one packet by default
    params.n = 1;

    int c;

    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, ":i:p:tun:h", long_options, &option_index);

        // The end of the options
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                // This option set a flag
                break;

            case 'i':
                if (optarg) {
                    params.interface = optarg;
                }
                break;

            case 'p':
                params.port = stoi(optarg);
                break;

            case 't':
                params.filters[TCP] = 1;
                break;

            case 'u':
                params.filters[UDP] = 1;
                break;

            case 'n':
                params.n = stoi(optarg);
                break;

            case 'h':
                usage(argv[0]);
                exit(0);
                break;

            case ':':
                if (optopt == 'i') {
                    // interface option without any argument
                    listInterfaces();
                    exit(0); // might need a little more polish
                } else {
                    // Bad option
                    usage(argv[0]);
                    exit(1);
                }

            case '?':
                // Bad option
                usage(argv[0]);
                exit(1);
                break;

            default:
                // Should never happen, if all options are handled
                abort();
        }
    }

    if (optind < argc) {
        usage(argv[0]);
        exit(1);
    }
};

string formatTimestamp(long seconds, long microseconds) {
    std::stringstream timestamp;
    char timestamp_arr[64];
    std::tm *time = std::localtime(&seconds);
    std::strftime(timestamp_arr, 64, "%Y-%m-%dT%H:%M:%S", time);
    timestamp << timestamp_arr;
    timestamp << "." << std::setfill('0') << std::setw(6) << microseconds << std::setw(0);
    
    char timezone_arr[5];
    std::strftime(timezone_arr, 64, "%z", time);
    string timezone_str = timezone_arr;
    // Time zone is +0100
    // Convert it to +01:00
    timestamp << timezone_str.substr(0, 3) << ":" << timezone_str.substr(3);
    
    return timestamp.str();
}

void printPacketContent(const char *buffer, int len) {
    const int LINE_LEN = 0x10;
    cout << std::hex << std::setfill('0') << std::setw(2);
    
    std::stringstream readableLine;
    
    int ceil_len = LINE_LEN * (1 + ((len - 1) / LINE_LEN));
    for (int i=0; i<ceil_len; i++) {
        // start of the line
        if (i % LINE_LEN == 0) {
            cout << "0x" 
                << std::setfill('0') << std::setw(4) << i
                << ": ";
        }
        
        if (i < len) {
            char c = buffer[i];
            cout << std::setw(2) << +static_cast<unsigned char>(c) << " ";
            
            c = isprint(c) ? c : '.';
            readableLine << c;
        } else {
            cout << "   ";
            readableLine << " ";
        }
        
        // end of the line
        if (i % LINE_LEN == LINE_LEN-1) {
            cout << readableLine.str() << endl;
            readableLine.str("");
        }
    }
    
    cout << std::dec << std::setw(0);
    cout << endl << endl;
}

string formatMAC(unsigned char *buffer) {
    std::stringstream output;
    output << std::hex << std::setfill('0') << std::setw(2);
    
    for (int i=0; i<6; i++) {
        output << +buffer[i];
        
        if (i != 5) {
            output << "-";
        } 
    }
    
    return output.str();
}

string formatIPv4(unsigned char *buffer) {
    std::stringstream output;
    
    for (int i=0; i<4; i++) {
        output << +buffer[i];
        
        if (i != 3) {
            output << ".";
        } 
    }
    
    return output.str();
}

string formatIPv6(unsigned char *buffer) {
    std::stringstream output;
    output << std::hex << std::setfill('0');
    
    for (int i=0; i<16; i++) {
        output << std::setw(2) << +buffer[i];
        
        if ((i%2 == 1) && (i != 15)) {
            output << ":";
        } 
    }
    
    return output.str();
}

void packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    cout << "timestamp: " << formatTimestamp(header->ts.tv_sec, header->ts.tv_usec) << endl;
    
    // This pointer always points to the currently processed header
    unsigned char *ptr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(packet));
    
    // Read the ethernet header
    cout << "src MAC: " << formatMAC(ptr+6) << endl;
    cout << "dst MAC: " << formatMAC(ptr) << endl;
    uint16_t etherType = *reinterpret_cast<uint16_t*>(ptr+12);
    ptr += 14;
    
    cout << "frame length: " << header->len << " bytes" << endl;
    
    unsigned char protocol, nextHeader;
    // decide, which header to read next
    switch (etherType) { // ethertype is still big endian
        case 0x0008:
            // ipv4 header
            cout << "src IP: " << formatIPv4(ptr+12) << endl;
            cout << "dst IP: " << formatIPv4(ptr+16) << endl;
            protocol = *(ptr+9);
            // if this packet is not TCP or UDP, skip reading ports
            if (!((protocol == 6) or (protocol == 17))) {
                goto end;
            }
            ptr += 20; // ipv4 options not supported
            break;
            
        case 0xDD86:
            // ipv6 header
            cout << "src IP: " << formatIPv6(ptr+8) << endl;
            cout << "dst IP: " << formatIPv6(ptr+24) << endl;
            nextHeader = *(ptr+6);
            // if this packet is not TCP or UDP, skip reading ports
            if (!((nextHeader == 6) or (nextHeader == 17))) {
                goto end;
            }
            ptr += 40; // ipv6 extension headers not supported
            break;
            
        case 0x0608:
            cout << "ethertype: arp (0x0806)" << endl;
            goto end;
            break;
            
        default:
            cout << "ethertype: "
            << std::hex << std::setfill('0') << std::setw(4) 
            << "0x" << ntohs(etherType)
            << std::dec << endl;
            goto end;
            break;
    }
    
    cout << "src port: " << ntohs(*reinterpret_cast<uint16_t*>(ptr)) << endl;
    cout << "dst port: " << ntohs(*reinterpret_cast<uint16_t*>(ptr+2)) << endl;
    
    end:
    cout << endl;
    printPacketContent(reinterpret_cast<const char*>(packet), header->len);
}


string constructFilter() {
    std::stringstream filter_expr;
    
    if (params.filters[ARP]) {
        if (filter_expr.str() != "") {
            filter_expr << " or ";
        }
        filter_expr << "arp";
    }
    
    if (params.filters[ARP]) {
        if (filter_expr.str() != "") {
            filter_expr << " or ";
        }
        filter_expr << "icmp";
    }
    
    if (params.filters[TCP] || params.filters[UDP]) {
        if (filter_expr.str() != "") {
            filter_expr << " or ";
        }
        
        filter_expr << "((";
        
        if (params.filters[TCP]) {
            filter_expr << "tcp";
        }
        
        if (params.filters[UDP]) {
            if (filter_expr.str() != "") {
                filter_expr << " or ";
            }
            filter_expr << "udp";
        }
        filter_expr << ")";
        
        if (params.port != 0) {
            filter_expr << " and (src port " << params.port << " or dst port " << params.port << ")";
        }
        
        filter_expr << ")";
    } else {
        if (params.port != 0) {
            if (filter_expr.str() != "") {
                filter_expr << " or ";
            }
            filter_expr << "(src port " << params.port << " or dst port " << params.port << ")";
        }
    }
    
    return filter_expr.str();
}

int main (int argc, char **argv) {
    parseParams(argc, argv);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    // Compiled filter expression
    struct bpf_program fp;
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */

    if (pcap_lookupnet(params.interface.c_str(), &net, &mask, errbuf) == -1) {
        cerr << "Can't get netmask for device " << params.interface << endl;
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(params.interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        cerr << "Could not open device " << params.interface
        << endl << errbuf << endl;
        exit(1);
    }

    string filter_expr = constructFilter();
    //filter_expr = "proto icmp";
    //cerr << "filter: " << filter_expr << endl;

    if (pcap_compile(handle, &fp, filter_expr.c_str(), 0, net) == -1) {
        cerr << "Couldn't compile filter " << filter_expr << endl
        << pcap_geterr(handle) << endl;
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Couldn't set filter " << filter_expr << endl
        << pcap_geterr(handle) << endl;
        exit(1);
    }


    pcap_loop(handle, params.n, packet_callback, nullptr);

    // free the filter
    pcap_freecode(&fp);
    // Close the device
	pcap_close(handle);

    return 0;
}
