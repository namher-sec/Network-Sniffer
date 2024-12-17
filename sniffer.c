#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <pcap/pcap.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>



void print_banner() {
    printf("  _____  _______ _______ _     _ _______ _______      _______ __   _ _____ _______ _______ _______  ______\n");
    printf(" |_____] |_____| |       |____/  |______    |         |______ | \\  |   |   |______ |______ |______ |_____/\n");
    printf(" |       |     | |_____  |    \\_ |______    |         ______| |  \\_| __|__ |       |       |______ |    \\_\n");
    printf("                                                                                                          \n");
}



  // Callback Function to handle captured packets
  void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    // Initialize pcap_dumper_t for saving packets
    pcap_dumper_t *dumper = (pcap_dumper_t *)user;

    /*This function pcap_dump() writes the packet (metadata and data) to the file
     * associated with the pcap_dumper_t object.
     */
    pcap_dump((u_char *)dumper, pkthdr, packet);


    // Print captured packet metadata i.e. time and packet length.
    printf("Packet captured at %s", ctime((const time_t *)&pkthdr->ts.tv_sec));
    printf("Packet length: %d bytes\n", pkthdr->len);

    //Typecast the packet pointer to Ethernet struct to retrieve Ethernet Header fields.
    struct ether_header *eth_hdr = (struct ether_header *)packet;


    printf("Ethernet Header:\n");

    printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
           eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
           eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
    printf("  EtherType: 0x%04x\n", ntohs(eth_hdr->ether_type));


    //add the length of Ethernet header to packet pointer so it moves to the next field i.e. IP Header.
    const u_char *ip_packet = packet + sizeof(struct ether_header);

    // Typecast the packet pointer to the IP header structure to get IP header fields.
    struct ip *ip_hdr = (struct ip *)ip_packet;

    // Define buffers to store source and destination IP addresses in string format.
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

    /*
     * The inet_ntoa() function converts the Internet host address in, given in binary (Big Endian), to a string in IPv4 dotted-decimal notation.
     * strcpy is then used to copy the ip into src_ip variable.
    */
    strcpy(src_ip, inet_ntoa(ip_hdr->ip_src));
    strcpy(dst_ip, inet_ntoa(ip_hdr->ip_dst));

    // Print Source and Destination IP
    printf("IP Header:\n");
    printf("  Source IP: %s\n", src_ip);
    printf("  Destination IP: %s\n", dst_ip);

    // Print additional IP Header fields.
    printf("  Version: %u\n", ip_hdr->ip_v);
    printf("  Header Length: %u bytes\n", ip_hdr->ip_hl * 4);
    printf("  Type of Service (TOS): 0x%02x\n", ip_hdr->ip_tos);
    printf("  Total Length: %u bytes\n", ntohs(ip_hdr->ip_len));
    printf("  Identification: 0x%04x (%u)\n", ntohs(ip_hdr->ip_id), ntohs(ip_hdr->ip_id));
    printf("  Fragment Offset: %u\n", ntohs(ip_hdr->ip_off) & IP_OFFMASK);
    printf("  Time to Live (TTL): %u\n", ip_hdr->ip_ttl);
    printf("  Protocol: ");

    switch (ip_hdr->ip_p) {
        case IPPROTO_TCP:
            printf("TCP\n");
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("ICMP\n");
            break;
        default:
            printf("Unknown (%u)\n", ip_hdr->ip_p);
            break;
    }
    printf("  Header Checksum: 0x%04x\n", ntohs(ip_hdr->ip_sum));

    printf("----------_--------_-------_------------\n");
}

int main(int argc, char *argv[]) {

    print_banner();

    char *device = "wlp58s0";                           // Determine the interface we want to sniff on.
    int packet_count = 15;                              // Number of packets we want to capture.
    char errbuf[PCAP_ERRBUF_SIZE];                      // Error buffer, Where errors are stored.
    struct bpf_program fp;                              // Compiled filter that will applied
    char filter[100];                                   // Filter expression.
    bpf_u_int32 mask;                                   // Network mask of our device
    bpf_u_int32 net;                                    // IP of the sniffing device


    int filter_choice;

    printf("Network Interface being used: %s\n", device);   // Print Network Interface to CLI.

    // Display available filters
    printf("Select a filter to apply:\n");
    printf("1. ICMP\n");
    printf("2. TCP\n");
    printf("3. UDP\n");
    printf("4. ALL (No Filter)\n");
    printf("Enter the number corresponding to the filter: ");
    scanf("%d", &filter_choice);

    // Set the filter expression based on the user's choice
    switch (filter_choice) {
        case 1:
            snprintf(filter, sizeof(filter), "icmp");
            break;
        case 2:
            snprintf(filter, sizeof(filter), "tcp");
            break;
        case 3:
            snprintf(filter, sizeof(filter), "udp");
            break;
        case 4:
            snprintf(filter, sizeof(filter), "");
            break;
        default:
            printf("Invalid choice! Defaulting to No Filter.\n");
            snprintf(filter, sizeof(filter), "");
            break;
    }


    printf("Selected Filter: %s\n", filter);

    /*
     pcap_lookupnet() is used to determine the IPv4 and network mask of the device we are using to
     sniff. Both netp and maskp are bpf_u_int32 pointers. errbuf is a buffer large enough to hold at least PCAP_ERRBUF_SIZE chars.

     int pcap_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf);

     1. our device
     2. bpf pointers
     3. error buffer

     https://en.wikipedia.org/wiki/Berkeley_Packet_Filter

     */

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get network mask of %s: %s\n", device, errbuf);
        net = 0;
        mask = 0;
    }

    // Session handle.
    pcap_t *packet;

    /*       Opening the device for sniffing:
     *
     * we use pcap_open_live() function which takes 5 arguments:
     * 1. our interface/device
     * 2. int snaplen which defines the number of bytes captured by pcap.
     * 3. int promisc which sets our interface in monitor mode if set to true.
     * 4. to_ms specifies the packet buffer timeout, meaning that you may have to wait x amount before   *  *    seeing any packets.
     * 5. char *ebuff which is a string that stores any error messages.
     */

    packet = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
    if (packet == NULL) {
        fprintf(stderr, "Error!! Could not open device %s: %s\n", device, errbuf);
        return 2;
    }

    // Compile the filter expression
    if (pcap_compile(packet, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't compile filter %s: %s\n", filter, pcap_geterr(packet));
        return 2;
    }

    //Apply/Set the compiled filter on Our Session Handle.
    if (pcap_setfilter(packet, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(packet));
        return 2;
    }


    // Open the capture file for saving packets
    pcap_dumper_t *dumper = pcap_dump_open(packet, "capturedpackets.pcap");
    if (dumper == NULL) {
        fprintf(stderr, "Error opening pcap dump file: %s\n", pcap_geterr(packet));
        return 2;
    }


    //Function to Capture Packets indefinitely.
    /*
     * It expects 4 arguments:
     * 1. capture handle
     * 2. number of packets/packet count.
     * 3. callback function.
     * 4. user defined data if needed.
     */

    int result = pcap_loop(packet, packet_count, packet_handler, (u_char *)dumper);

    if (result < 0) {
        printf("Error in pcap_loop: %s\n", pcap_geterr(packet));
    } else {
        printf("Capture finished\n");
    }

    // Close the pcap dump file and packet capture session
    pcap_dump_close(dumper);

    //Close the Sessio handle.
    pcap_close(packet);

    return 0;
}
