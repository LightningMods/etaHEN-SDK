#ifndef _TYPES_H
#define _TYPES_H

typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;
typedef void *ScePthread;
typedef void *ScePthreadAttr;

#endif