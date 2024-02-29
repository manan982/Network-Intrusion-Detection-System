#include "queue.h"

#include <stdio.h>
#include <stdlib.h>

//Lab 3 queue code  
struct queue * QueueCreation(void) {
    struct queue *q  = (struct queue *)malloc(sizeof(struct queue));
    q->head=NULL;
    q->tail=NULL;
    return (q); 
}

void QueueDestruction(struct queue *q) {
    while(!isempty(q)){
        dequeue(q);
    }
    free(q); //removes the queue and frees it from memory
}

int isempty(struct queue *q) {
    return(q->head == NULL);
}

void enqueue(struct queue *q, struct element * item) {

    //add a node to the queue 

    struct node * new_node = (struct node *)malloc(sizeof(struct node));
    new_node->e = item;
    new_node->next=NULL;
    
    if (isempty(q)) {
        q->head=new_node;
        q->tail=new_node;
    }
    else {
        q->tail->next=new_node;
        q->tail=new_node;
    }
}

//removes the initial node 
void dequeue(struct queue *q) {
    struct node *head_node;
    head_node=q->head;
    q->head=q->head->next;
    if(q->head==NULL) {
        q->tail=NULL;
        free(head_node);
    }
}