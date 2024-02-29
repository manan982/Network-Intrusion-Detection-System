#include "sniff.h"
#include "queue.h"
#include "dispatch.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>


#define THREAD_NO 2 //2 threads ideal, as VM uses 1 core.
pthread_t tid[THREAD_NO]; // stores thread IPs in array

//initialises variables to keep count of instances of malicious packets 
volatile unsigned long long TrackSyn;
volatile unsigned long long TrackARP; 
volatile unsigned long long TrackBlackList;
volatile unsigned long long TrackIPs;

struct queue *queueWorker; 

//will be called during pcaploop() function, and sends packets to dispatch()
void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
  if(packet != NULL) {
    dispatch(header,packet,1);
  }
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  signal(SIGINT, intrusionDetection);
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}


// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
  queueWorker = QueueCreation(); //makes a work queue 
  
  char errbuf[PCAP_ERRBUF_SIZE];
  for (int i = 0; i <THREAD_NO; i++) { //number of worker threads we intialised before are created.
    pthread_create(&tid[i],NULL,handle_conn,NULL);
  }
  
  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  signal(SIGINT, intrusionDetection); //upon clicking ctrl c ends packet sniffing and prints out the report
  pcap_loop(pcap_handle,-1,callback,NULL); //loops infinetly due to -1. Passes packets to callback function
  QueueDestruction(queueWorker);
}
