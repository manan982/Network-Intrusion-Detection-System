#include "dispatch.h"
#include "sniff.h"
#include "queue.h"
#include "analysis.h"

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

pthread_cond_t conditional = PTHREAD_COND_INITIALIZER;
pthread_mutex_t lockingMutex = PTHREAD_MUTEX_INITIALIZER;
//synchronises threads using mutex locks, meaning a singular variable is updated at once by a thread

void *handle_conn(void *arg){ 
  //all threads will carry out this 
  //pthread_create executes the thread code for total number of threads. (2 in this case)
  while(1) {
    pthread_mutex_lock(&lockingMutex); //
    
    while (isempty(queueWorker)) {
      pthread_cond_wait(&conditional,&lockingMutex);
    } // wait until item enters queue if queueWorker is empty currently
    struct element *e = queueWorker->head->e;
    
    struct pcap_pkthdr *header = e->hdr;
    const unsigned char *packet = e->pkt;
    int ver = e->v;
    dequeue(queueWorker);
    pthread_mutex_unlock(&lockingMutex); // lock and unlock mutex as handling a global variable
    analyse(header,packet, ver); //calls analyse 
  }
  return NULL;
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {

  pthread_mutex_lock(&lockingMutex);

  // workQueue adds packet to be enqueued. 
  struct element *e = (struct element *)malloc(sizeof(struct element));
  
  e->hdr = header; 
  e->pkt = packet;
  e->v = verbose;
  enqueue(queueWorker,e);
  //put packet in working queue 
  pthread_mutex_unlock(&lockingMutex);
  pthread_cond_broadcast(&conditional);
}

//prints out report upon entering control c 
void intrusionDetection(int sig){
  
  printf("Intrusion Detection Report:\n");
  printf("%llu SYN packets detected from %llu different IPs (syn attack)\n",TrackSyn,TrackIPs);
  printf("%llu ARP responses (cache poisnoning)\n",TrackARP);
  printf("%llu Blacklist violations \n",TrackBlackList);
  exit(EXIT_SUCCESS);
}
