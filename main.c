#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <time.h>

#define CHECK_FLAG(flags, mask) (((flags) & (mask)) == (mask))

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;

    // Parse Ethernet header
    eth_header =(struct ether_header*)packet;

    // Ensure it's an IP packet
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        printf("Not an IP packet. Skipping ... \n\n");
        return;       
    }

    // Parse IP header
    ip_header = (struct ip*)(packet + sizeof(struct ether_header));

    // Print packet info
    printf("Packet capture at: %s", ctime((const time_t*)&pkthdr->ts.tv_sec));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));    
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));    

    // Check if it's TCP
    if (ip_header->ip_p == IPPROTO_TCP)
    {
        tcp_header =(struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destnation Port: %d\n", ntohs(tcp_header->th_dport));
    }

    printf("\n");    
}

void process_packet( u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet){
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    int ip_header_len;

    // Skip Ethernet heade
    ip_hdr = (struct ip*)(packet + 14);

    // IS it IPv4
    if (ip_hdr->ip_v != 4)
    {
        return;
    }

    ip_header_len = ip_hdr->ip_hl * 4;
    
    //Get TCP header
    tcp_hdr =(struct tcphdr*)((u_char *)ip_hdr + ip_header_len);
    
    // Check frags combine
    if (CHECK_FLAG(tcp_hdr->th_flags, TH_SYN) && !CHECK_FLAG(tcp_hdr->th_flags, TH_ACK)){
        printf("SYN: %s:%d -> %s:%d\n",
            inet_ntoa(ip_hdr->ip_src), ntohs(tcp_hdr->th_sport),
            inet_ntoa(ip_hdr->ip_dst), ntohs(tcp_hdr->th_dport));

    }
    else if (CHECK_FLAG(tcp_hdr->th_flags, TH_SYN | TH_ACK)){
        printf("SYN-ACK: %s:%d -> %s:%d\n",
            inet_ntoa(ip_hdr->ip_src), ntohs(tcp_hdr->th_sport),
            inet_ntoa(ip_hdr->ip_dst), ntohs(tcp_hdr->th_dport));
    }
    else if (CHECK_FLAG(tcp_hdr->th_flags, TH_ACK) && !CHECK_FLAG(tcp_hdr->th_flags, TH_SYN)){
        printf("ACK: %s:%d -> %s:%d\n",
            inet_ntoa(ip_hdr->ip_src), ntohs(tcp_hdr->th_sport),
            inet_ntoa(ip_hdr->ip_dst), ntohs(tcp_hdr->th_dport));
    } 
    
    
}
// Function to list all avaliable network interface
void list_interfaces(){
    pcap_if_t *all_devices;
    pcap_if_t *device;
    int i = 1;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the device list
    if (pcap_findalldevs(&all_devices, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    // Print the list
    for (device = all_devices; device; device= device->next)
    {
        printf("%d. %s", i++, device->name);
        if (device->description)
        {
            printf(" (%s)", device->description);
        }
        printf("\n");        
    }
    printf("\n");

    // Free the device list   
    pcap_freealldevs(all_devices);
}

// Function to get device by number from list
char* get_device_by_number(int device_num){
    pcap_if_t *all_devices;
    pcap_if_t *device;
    int i = 1;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* selected_dev = NULL;

    if(pcap_findalldevs(&all_devices, errbuf) == -1){
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    // Find the selected device
    for (device = all_devices; device; device = device->next)
    {
        if (i == device_num)
        {
            selected_dev = strdup(device->name);
            break;
        }
        i++;        
    }

    pcap_freealldevs(all_devices);
    return selected_dev;
}

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;                     // session handle
    struct bpf_program fp;              // Compiled filter
    char filter_exp[] = "ip";           // Filter expression
    bpf_u_int32 net;                    // Network address
    bpf_u_int32 mask;                   // Network mask
    char *device;                        // Selected network interface
    int choice;

    // List 
    list_interfaces();

    // Get user's chois
    printf("Enter the interface number (1,2,3, ...): ");
    scanf("%d", &choice);

    // Get the device name for the given number
    device = get_device_by_number(choice);
    if (device == NULL)
    {
        fprintf(stderr, "Invalid interface number. \n");
        return 1;
    }

    printf("Selected device: %s\n", device);

    //Get network address and mask
    if(pcap_lookupnet(device, &net, &mask, errbuf) == -1) 
    {
        fprintf(stderr, "Cab't get netmask for device %s\n", errbuf);
        net=0; mask=0;
    }

    // Open device for capturing 
    handle = pcap_open_live(device, // device
                            BUFSIZ, // snapshot length 
                            1,      // promiscuous mode
                            1000,   // read timeout (ms)
                            errbuf);// error buffer    
    if (handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        free(device);
        return 1;        
    }

    // Device support Ethernet?
    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr, "Device dot'n support Ethernet");
        return 2;
    }

    // Compile and apply the filter
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        free(device);
        return 3;
    }

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        free(device);
        return 4;
    }

    // Start capturing packets
    printf("Starting packet capture on %s. Press Ctrl+C to stop. \n\n", device);
    pcap_loop(handle, -1, process_packet, NULL);

    // Clean uo
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}