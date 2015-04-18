#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef enum {
 SEND_HELLO,
 STOP_HELLO,
 SESSION_STATE,
 VC_INFO,
 WITHDRAW_PW,
 RELEASE_PW,
 IN_PW_LABEL,
 OUT_PW_LABEL,
 RCV_LDP_WITHDRAW_MSG,
 RCV_LDP_RELEASE_MSG
} ldp_msg_type;

// used by SEND_HELLO, STOP_HELLO
typedef struct remote_pe_ip{
	struct in_addr remote_ip;
} remote_pe_ip;

typedef struct session_state{
	struct in_addr remote_ip;
	u_char state;  //0: no session, 2: yes
} session_state;

// used by VC_INFO, WITHDRAW_PW, RELEASE_PW
typedef struct vc_info{
	u_short vc_type;
	u_short vpn_id;
	u_long label;
	struct in_addr remote_ip;
} vc_info;

// used by IN_PW_LABEL, OUT_PW_LABEL
typedef struct pw_label_info{
	u_short vpn_id;
	struct in_addr remote_ip;
	u_long label;
} pw_label_info;

// used by RCV_WITHDRAW_MSG, RCV_RELEASE_MSG
typedef struct withdraw_pw_msg{
	u_short vpn_id;
	struct in_addr remote_ip;
} withdraw_pw_msg; 

typedef struct vpn_ldp_xmsg{
	u_short mid;
	ldp_msg_type type;
	union {
		remote_pe_ip rpi;
		session_state ss;
		vc_info vi;
		pw_label_info pli;
		withdraw_pw_msg wpm;
	}u;
} vpn_ldp_xmsg;

