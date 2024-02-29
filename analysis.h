#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

typedef union {
  struct {
    char *array;
    size_t old; //if ip address has been encountered before 
    size_t capacity; //size of dynamic array
  };
} DynamicArray;


extern DynamicArray IPAddressArray;
// makes dynamic array structure global for storing IP address

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);

#endif
