#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);

extern struct queue *queueWorker;

extern volatile unsigned long long TrackSyn;
extern volatile unsigned long long TrackARP;
extern volatile unsigned long long TrackBlackList;
extern volatile unsigned long long TrackIPs;

//

#endif
