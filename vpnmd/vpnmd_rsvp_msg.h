#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

//used by SETUP_TUNNEL, WITHDRAW_TUNNEL, RELEASE_TUNNEL, RCV_PATHTEAR_MSG, RCV_RESVTEAR_MSG
typedef struct remote_pe_id{
	struct in_addr remote_ip;
} remote_pe_id;

//when RESV is transmitted
typedef struct in_tunnel_label{
	struct in_addr remote_ip;
	u_long label;
	u_char in_if[8];
} in_tunnel_label;

//when RESV is received
typedef struct out_tunnel_label{
	struct in_addr remote_ip;
        u_long label;
        u_char out_if[8];
	struct in_addr next_hop_ip;
} out_tunnel_label;

