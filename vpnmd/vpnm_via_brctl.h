/*
This code used to commnuicate with brctld via VTY socket
*/

#ifndef _VPNM_VIA_BRCTL_H_
#define _VPNM_VIA_BRCTL_H_

int set_vpls_bridge(const char* br_name);
int clear_vpls_bridge(const char* br_name);

int add_bridge(const char *br_name);
int add_if(const char *br_name,const char *if_name);
int del_if(const char *br_name,const char *if_name);

#endif
