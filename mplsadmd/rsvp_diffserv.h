/* GIOVANNA for DIFFSERV: new data object for L-LSP DIFFSERV object*/

#ifdef DIFFSERV
#ifndef _rsvp_diffserv_h_
#define _rsvp_diffserv_h_

#include <sys/types.h>

typedef struct ds {

        u_int16_t  reserved;
        u_int16_t  PHBid_ds;


}DIFFSERV_LLSP;

//#define diffserv DIFFSERV_LLSP
#endif  /* _rsvp_diffserv_h_*/
#endif


