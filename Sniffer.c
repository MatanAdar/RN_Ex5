#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>

/* Ethernet header */
struct ethheader
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader
{
  unsigned char iph_ihl : 4,       // IP header length
      iph_ver : 4;                 // IP version
  unsigned char iph_tos;           // Type of service
  unsigned short int iph_len;      // IP Packet length (data + header)
  unsigned short int iph_ident;    // Identification
  unsigned short int iph_flag : 3, // Fragmentation flags
      iph_offset : 13;             // Flags offset
  unsigned char iph_ttl;           // Time to Live
  unsigned char iph_protocol;      // Protocol type
  unsigned short int iph_chksum;   // IP datagram checksum
  struct in_addr iph_sourceip;     // Source IP address
  struct in_addr iph_destip;       // Destination IP address
};

//Application Header
struct app_header
{
  uint32_t timestamp;             //the time that the packet was sent
  uint16_t length;                //total length of the packet

  union                          // all the flags and the status is in here and we taking specific bytes to each flag
  {
    uint16_t flags;
    uint16_t _ : 3, c_flag : 1, s_flag : 1, t_flag : 1, status : 10;   //the status code of the response
  };

  uint16_t cache;                //'Max-Age' value for the cache.
  uint16_t __;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  //open file by our id names
  FILE *file;
  file = fopen("213861529_209321553.txt", "a+");
  if (file == NULL)
  {
    printf("unable to create file");
  }

  struct ethheader *eth = (struct ethheader *)packet;

  // Find where the IP header starts, and typecast it to the IP Header structure
  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  unsigned short iphdrlen = (ip->iph_ihl) * 4;

  // Find where the tcp header starts, and typecast it to the tcp header structure
  struct tcphdr *tcphdr= (struct tcphdr *)(packet + iphdrlen + sizeof(struct ethheader));
  unsigned int data_offset = (tcphdr->th_off) * 4;

  // Find where the aaplication header starts, and typecast it to the application Header structure
  struct app_header *apphdr= (struct app_header *)(packet + sizeof(struct ethheader) + iphdrlen + data_offset);


  // print the timestamp as a human readable date and time
  time_t rawtime = header->ts.tv_sec;
  struct tm date;
  char buf[80];
  date = *localtime(&rawtime);
  strftime(buf, sizeof(buf), "%a %d-%m-%Y %H:%M:%S", &date);


  if (ntohs(eth->ether_type) == 0x0800)
  { // 0x0800 is IP type

    /* determine protocol */
    switch (ip->iph_protocol)
    {
    case IPPROTO_TCP:

      printf("   Protocol: TCP\n");

      fprintf(file, "                        TCP header\n");
      fprintf(file, "** ********************************************************************\n");
      fprintf(file, "           source_ip: %s\n", inet_ntoa(ip->iph_sourceip));
      fprintf(file, "           dest_ip: %s\n", inet_ntoa(ip->iph_destip));
      fprintf(file, "           source_port: %hu\n", ntohs(tcphdr->source));
      fprintf(file, "           dst_port: %hu\n", ntohs(tcphdr->dest));
      fprintf(file, "           timestap: %u (%s)\n", ntohl(apphdr->timestamp), buf);
      fprintf(file, "           total_length:%u \n", ntohs(apphdr->length));
      fprintf(file, "           cache_flag: %u \n", (ntohs(apphdr->flags) >> 12) & 1);
      fprintf(file, "           step_flag: %u \n", (ntohs(apphdr->flags) >> 11) & 1);
      fprintf(file, "           type_flag: %u \n", (htons(apphdr->flags) >> 10) & 1);
      fprintf(file, "           status_code: %u \n", htons(apphdr->flags) & 0x3ff);
      fprintf(file, "           cache_control:%u \n", ntohs(apphdr->cache));
      fprintf(file, "           data: \n");

      // exctract data from the application header and print it to the file
      u_char *data = (u_char *)(packet + sizeof(struct ethheader) + iphdrlen + data_offset + sizeof(apphdr));
      unsigned int data_size = ntohs(ip->iph_len) - (iphdrlen + data_offset);

      if (data_size > 0)
      {
        for (int i = 0; i < data_size; i++)
        {
          if (!(i & 15))
          {
            fprintf(file, "\n %04X: ", i);
          }
          fprintf(file, "%02X: ", ((unsigned char *)data)[i]);
        }
      }
      else
      {
        fprintf(file, "                     dont receive any data!");
      }
      fprintf(file, "\n");
      fprintf(file, "**********************************************************************\n");
      fclose(file);
      return;

    case IPPROTO_UDP:
      printf("   Protocol: UDP\n");
      return;

    case IPPROTO_ICMP:
      printf("   Protocol: ICMP\n");
      return;

    default:
      printf("   Protocol: others\n");
      return;
    }
  }
}

// void got_packet(u_char *args, const struct pcap_pkthdr *header,
//                 const u_char *packet)
// {
//   printf("Got a packet\n");
// }

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); // Close the handle

  return 0;
}