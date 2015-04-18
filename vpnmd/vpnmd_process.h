/*
The search_vpn2pw_entry ,search_vpn2pw_entry need to rewrite ...
VPN M管理很多vpn 每一個VPN所搭配的PW 、Tunnel 是匹配的，但是其他的VPN 
所使用的PW 會有相同 Tunnel 必須再使用一個strure 去紀錄哪些VPN 使用的PW
搭配相同的Tunnel 
*/

#include "vpnmd_table.h"
#define WITHDRAW_IN 0
#define WITHDRAW_OUT 1
#define WITHDRAW_DOIT -1

//vpn_entry process function block
vpn_entry *search_vpn_node(vpn_entry * vpn,int vpn_id);
int qurray_vpn_entry(struct vty *vty,vpn_entry * vpn,int vpn_id);
int set_customer_facig_port(int vpn_id,const char *ifname);
int delete_customer_facig_port(int vpn_id, const char *ifname);
int add_port_info (struct vty *vty,vpn_entry * vpn, int port_id);
int del_port (vpn_entry * vpn, int port_id);
int del_vpn_info(vpn_entry *vpn,int vpn_id);
int del_pw_info(vpn_entry *vpn,unsigned long ip,int state);
int delete_pw(vpn_entry *vpn,unsigned long ip);
//end vpn_entry process function block

//tunnel process function block
int setup_tunnel(struct vty *vty,char *src_ip,char *dst_ip,int lsp_id);
int add_new_tunnel_entry (unsigned long dst_ip,tunnel_entry *tunnel);
int qurray_tunnel_entry(unsigned long dst_ip,tunnel_entry * tunnel);
int withdraw_pw(vpn_entry *vpn,unsigned long ip,int state);
tunnel_entry *search_tunnel_node(tunnel_entry * tunnel,unsigned long dst_ip);

//end tunnel process

//setup PW information
int setup_pw_info(vpn_entry *vpn,unsigned long ip,int set_state);
int add_pw_info(vpn_entry *vpn,unsigned long ip);
//end setup PW information

//need to rewrite search - quarry PW information function code
int search_vpn2pw_entry(vpn_entry *vpn,unsigned long ip);
int search_pw_info(vpn_entry *vpn,unsigned long ip);
//end need to rewrite search - quarry PW information function code

//quarry entry process function call
int quarry_pw_info(vpn_entry *vpn,unsigned long ip,int vpn_id);
//end quarry entry process function call

//get PW_entry
pw_info_entry *get_pw_entry(vpn_entry *vpn,unsigned long ip);

