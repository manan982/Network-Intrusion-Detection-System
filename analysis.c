#include "analysis.h"
#include "sniff.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>

DynamicArray IPAddressArray; //dynamically growing array to store unique IP headers;

//initialise mutex lock to synchronise threads
pthread_mutex_t incrementMutex = PTHREAD_MUTEX_INITIALIZER;

//used to add unique ip addresses to array
void insertArray(DynamicArray *a, int element) {
  if (a->old == a->capacity) {
    a->capacity *= 2; // whenever run out of space in array, double the size of the array
    a->array = (int *)realloc(a->array, a->capacity * sizeof(int));
  }
  a->array[a->old++] = element;
  //after using array updates value of a->old
}


void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  
  struct tcphdr *headerTCP;
  struct ip *headerIP;
  unsigned char *payload;
  char *sourceAddress;
  
  int nonUniqueIP = 0;
  unsigned char LocatedSyn = 0; //used to track occurunces of all malicious packets
  unsigned char LocatedARP = 0;
  unsigned char LocatedBL = 0;
  
  //Decoding packet header 
  struct ether_header *headerEther = (struct ether_header *) packet;
  const unsigned char *payloadEther = ETH_HLEN + packet;
  if (ntohs(headerEther->ether_type) == ETH_P_IP) {
    headerIP = (struct ip *) payloadEther;
    const unsigned char *payloadIP = ETH_HLEN + headerIP->ip_hl*4 + packet ;
    
    if (headerIP->ip_p == IPPROTO_TCP) {
      headerTCP = (struct tcphdr *) payloadIP;
      payload = ETH_HLEN + headerIP->ip_hl * 4 + headerTCP->doff * 4 + packet ;
    }
  }

  //blacklist scan if port is equal to 80
  if (headerTCP != NULL) {
    if (ntohs(headerTCP->dest) == 80) { 
      unsigned char *substr = strstr(payload, "Host:");
      if (substr != NULL) {
        if (strstr(substr, "google.co.uk") != NULL || strstr(substr, "bbc.com") != NULL ) { //2 websites which should be blacklisted
          LocatedBL++;
          printf("==============================\n");
          printf("Blacklisted URL Detected\n");
          printf("Source IP Address: %s\n",inet_ntoa(headerIP->ip_src)); //converts network address into printable string
          printf("Destination IP Address: %s\n",inet_ntoa(headerIP->ip_dst));
        }
      }
    }
  }

  //finding all syn packets and the unique ips
  if (headerTCP != NULL) {
    if ((headerTCP->th_flags & (TH_SYN | TH_URG | TH_ACK | TH_PUSH)) == TH_SYN) {
      LocatedSyn++;
      sourceAddress = inet_ntoa(headerIP->ip_src); //converts network address into string
      
      for (int i = 0; i < IPAddressArray.old; i++) { //looking for unique ip address in the array
        if (IPAddressArray.array[i] == sourceAddress) {
          nonUniqueIP = 1; //packet encountered before 
          break;
        }
      }
      if (nonUniqueIP == 0) {
        insertArray(&IPAddressArray,sourceAddress); //add to array iff unique
      }
    } 
  }
  
  //ARP search fo find cache poisoning attacks. ETHERTYPE_ARP as a protocol
  if (ntohs(headerEther->ether_type) == ETHERTYPE_ARP) {
    LocatedARP++;
  }

  
  //Add each instance to the total global varibales that track count
  pthread_mutex_lock(&incrementMutex); //lock and unlock when assinging global variable values.
  TrackSyn += LocatedSyn;
  TrackIPs = IPAddressArray.old;
  TrackARP += LocatedARP;
  TrackBlackList += LocatedBL;
  pthread_mutex_unlock(&incrementMutex);

}
