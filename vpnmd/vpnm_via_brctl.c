#include <stdio.h>
#include <stdlib.h>
#include "connect_daemon.h"
#include "vpnm_via_brctl.h"

static void nic_info_set(const char *if_name);
static void nic_info_clear(const char *if_name);
static void br_info_set(const char *br_name);
static void br_info_clear(const char *br_name);
static void iptables_set();
static void iptables_clear();

static int del_bridge(const char *br_name);

char buf[1024];

static void nic_info_set(const char *if_name){
	//ifconfig if_name 0.0.0.0 up 
	sprintf(buf,"ifconfig %s 0.0.0.0 up",if_name);
	system(buf);
}
static void nic_info_clear(const char *if_name){
	//ifconfig if_name 0.0.0.0 down 
	sprintf(buf,"ifconfig %s 0.0.0.0",if_name);
	system(buf);
}

static void br_info_set(const char *br_name){
	//need to adding new parameter to set vpls bridge nic informations
	//ifconfig br100 10.0.0.97  netmask 255.255.255.0 broadcast 10.0.0.255 up
	//echo "1" > /proc/sys/net/ipv4/ip_forward  --> zebra also can set it.
  //route add -net 10.0.0.0/24 dev br100
	sprintf(buf,"ifconfig %s 10.0.0.97  netmask 255.255.255.0 broadcast 10.0.0.255 up",br_name);
	system(buf);
	system("echo \"1\" > /proc/sys/net/ipv4/ip_forward ");
	sprintf(buf,"route add -net 10.0.0.0/24 dev %s",br_name);
	system(buf);
}
static void br_info_clear(const char *br_name){
	sprintf(buf,"ifconfig %s down",br_name);
	system(buf);
	del_bridge(br_name);
}

static void iptables_set(){
/*iptables -P FORWARD DROP
iptables -F FORWARD
iptables -I FORWARD -j ACCEPT
iptables -I FORWARD -j DROP
iptables -A FORWARD -j DROP
iptables -x -v --line-numbers -L FORWARD

iptables -D FORWARD 1
iptables -x -v --line-numbers -L FORWARD
*/
system("iptables -P FORWARD DROP");	
system("iptables -F FORWARD");	
system("iptables -I FORWARD -j ACCEPT");	
system("iptables -I FORWARD -j DROP");	
system("iptables -A FORWARD -j DROP");	
system("iptables -D FORWARD 1");	
}
static void iptables_clear(){
	//iptables -D FORWARD 1
	//iptables -D FORWARD 1
	system("iptables -D FORWARD 1");
	system("iptables -D FORWARD 1");
}

int add_bridge(const char *br_name){
 
 connect_daemon(VTYSH_INDEX_BRCTLD);
 sprintf(buf,"add bridge %s",br_name);
 vtysh_client_execute(&vtysh_client[VTYSH_INDEX_BRCTLD], buf, stdout);
 printf("buf :%s\n",buf);
 exit_daemon(VTYSH_INDEX_BRCTLD);
 return 0;
}
static int del_bridge(const char *br_name){

connect_daemon(VTYSH_INDEX_BRCTLD);
sprintf(buf,"del bridge %s",br_name);
vtysh_client_execute(&vtysh_client[VTYSH_INDEX_BRCTLD], buf, stdout);
exit_daemon(VTYSH_INDEX_BRCTLD);
return 0;
}
int add_if(const char *br_name,const char *if_name){
	
connect_daemon(VTYSH_INDEX_BRCTLD);
sprintf(buf,"addif bridge %s if %s",br_name,if_name);
vtysh_client_execute(&vtysh_client[VTYSH_INDEX_BRCTLD], buf, stdout);
exit_daemon(VTYSH_INDEX_BRCTLD);
nic_info_set(if_name);
return 0;
}
int del_if(const char *br_name,const char *if_name){
	
connect_daemon(VTYSH_INDEX_BRCTLD);
sprintf(buf,"delif bridge %s if %s",br_name,if_name);
vtysh_client_execute(&vtysh_client[VTYSH_INDEX_BRCTLD], buf, stdout);
exit_daemon(VTYSH_INDEX_BRCTLD);
nic_info_clear(if_name);
return 0;
}

/*
Setting VPLS Bridge 
./brctl addbr br100
./brctl addif br100 eth1
./brctl addif br100 mpls100

ifconfig eth1 0.0.0.0 up
ifconfig mpls100 0.0.0.0 up
ifconfig br100 10.0.0.97  netmask 255.255.255.0 broadcast 10.0.0.255 up
echo "1" > /proc/sys/net/ipv4/ip_forward
route add -net 10.0.0.0/24 dev br100

iptables -P FORWARD DROP
iptables -F FORWARD
iptables -I FORWARD -j ACCEPT
iptables -I FORWARD -j DROP
iptables -A FORWARD -j DROP
iptables -x -v --line-numbers -L FORWARD

iptables -D FORWARD 1
iptables -x -v --line-numbers -L FORWARD
*/

int set_vpls_bridge(const char *br_name){
	br_info_set(br_name);
	iptables_set();
	return 0;	
}

int clear_vpls_bridge(const char* br_name){
	br_info_clear(br_name);
	iptables_clear();
	return 0;
}
