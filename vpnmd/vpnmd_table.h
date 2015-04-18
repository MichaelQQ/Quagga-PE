#include <sys/types.h>
#include <arpa/inet.h>

#include "zebra.h"
#include "command.h"
#include "log.h"

#define USED	1
#define UNUSED	0
//setup tunnel state 
#define NOT_READY       0x00
#define PROCESSING      0x01
#define READY           0x02

#define TUNNEL_TAB_SIZE 100
#define VPN_TAB_SIZE    100
typedef struct tunnel_entry {
	struct in_addr remote_ip;
	u_long in_tunnel_label;
	u_long out_tunnel_label;
	u_char in_if[20];
	u_char out_if[20];
	int nhlfe_key;
	u_char in_state;  //NOT_READY, PROCESSING, or READY
	u_char out_state;  //NOT_READY, PROCESSING, or READY
	int in_lsp_id;
	int out_lsp_id;
	struct in_addr next_hop_ip;
	u_char in_use;  //USED or UNUSED
	struct tunnel_entry *next; //link list 
} tunnel_entry;

typedef struct port_id_entry {
	struct port_id_entry *next;
	u_short port_id;
	u_char iface[20];
} port_id_entry;

typedef struct pw_info_entry{
	struct pw_info_entry *next;
	u_long in_pw_label;
	u_long out_pw_label;
	u_char in_state;  //NOT_READY, PROCESSING, or READY
	u_char out_state;  //NOT_READY, PROCESSING, or READY
	struct in_addr remote_ip;
	u_char iface[20]; //mapping to Tunnel interface
} pw_info_entry;

typedef struct vpn_entry{
//	u_short vpn_id;
	int vpn_id; //add by here for only one vpn entry
	port_id_entry *port_id_ptr;
	pw_info_entry *pw_info_ptr;
	u_char in_use; //USED or UNUSED
	struct vpn_entry *next;
} vpn_entry;

int show_vpls_info(struct vty *vty,vpn_entry *vpn,tunnel_entry *tunnel);
//int show_vpls_info(vpn_entry *);//only for testing function 
int show_tunnel_info(struct vty *vty,tunnel_entry *);
int show_pw_info(struct vty *vty,vpn_entry *vpn);
void show_port_info(port_id_entry *port);
//process PW function
pw_info_entry *fetch_pw_by_ip(vpn_entry *vpn,unsigned long dst_ip);
//end process PW function
