#ifndef _LDP_TRACE_H_
#define _LDP_TRACE_H_

#include <stdio.h>
#include "ldp_struct.h"

extern uint32_t ldp_traceflags;
extern uint8_t trace_buffer[16834];
extern int trace_buffer_len;

#if 0
1 2 3 4 5 6 7 8
  12345678901234567890123456789012345678901234567890123456789012345678901234567890
#endif
#define LDP_TRACE_OUT(handle,args...) {				\
    if(trace_buffer_len == 0) {					\
      trace_buffer_len += sprintf(trace_buffer,"OUT: " args);\
    } else {							\
      trace_buffer_len += sprintf(trace_buffer+trace_buffer_len,args);\
    }								\
    if(trace_buffer[strlen(trace_buffer)-1] == '\n') {		\
      fprintf(stderr,"%s",trace_buffer);			\
      trace_buffer_len = 0;					\
    }								\
}
#define LDP_TRACE_LOG(handle,class,type,args...) {		\
  if(type & ldp_traceflags) {					\
    LDP_TRACE_OUT(handle,args);					\
  }								\
}
#define LDP_TRACE_PKT(handle,class,type,header,body) {		\
  if(type & ldp_traceflags) {					\
    header;							\
    body;							\
  }								\
}
#define LDP_DUMP_PKT(handle,class,type,func) {			\
  if(type & ldp_traceflags) {					\
    func;							\
  }								\
}
#define LDP_PRINT(data,args...) {				\
  if(ldp_traceflags & LDP_TRACE_FLAG_DEBUG) {			\
    fprintf(stderr, "PRT: " args);				\
  }								\
}
#define LDP_ENTER(data,args...) {				\
  if(ldp_traceflags & LDP_TRACE_FLAG_DEBUG) {			\
    fprintf(stderr, "ENTER: " args);				\
    fprintf(stderr, "\n");					\
  }								\
}
#define LDP_EXIT(data,args...) {				\
  if(ldp_traceflags & LDP_TRACE_FLAG_DEBUG) {			\
    fprintf(stderr, "EXIT: " args);				\
    fprintf(stderr, "\n");					\
  }								\
}

#endif
