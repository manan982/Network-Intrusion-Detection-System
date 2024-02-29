#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

void intrusionDetection(int sig);

extern void * handle_conn (void* arg); //globalises thread code function

#endif
