
struct queue *QueueCreation(void);

void QueueDestruction(struct queue *q);

struct node {
    struct element *e; //element of the thread
    struct node *next;
};

struct queue {
    struct node *head;
    struct node *tail;
};

struct element {
    struct pcap_pkthdr *hdr;
    const unsigned char *pkt;
    int v;
};


int isempty(struct queue *q);

void enqueue(struct queue *q, struct element * item);

void dequeue(struct queue *q);

