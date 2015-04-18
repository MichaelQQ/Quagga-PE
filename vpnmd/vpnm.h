
#include "vpnmd_table.h"

typedef struct nic_info{
	char if_name[5];
	char ip[20];
	int lsp_id; //temporary to used ..this information will be get by rsvpd
}nic_info;        

vpn_entry *vpn_new(void);
vpn_entry *vpn_new_more(vpn_entry *vpn);
int vpn_finish(vpn_entry *,int vpn_id);
vpn_entry *vpn_get(void);

tunnel_entry *tunnel_new(void);
tunnel_entry *tunnel_new_more(tunnel_entry *);
tunnel_entry *tunnel_finish(tunnel_entry *);
tunnel_entry *tunnel_get(void);
int del_tunnel_entry(tunnel_entry *tunnel,unsigned long dst_ip);

//NIC process function
nic_info *nic_get(void);
nic_info *nic_new(void);
