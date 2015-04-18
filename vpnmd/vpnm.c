#include <stdio.h>
#include <stdlib.h>
#include "vpnm.h"

/* VPN instance top. */
vpn_entry *vpn_top=NULL;

/* TUNNEL instance top. */
tunnel_entry *tunnel_top=NULL;

/* nic informatin */
nic_info *nic_top=NULL;

//only one vpn entry ;
vpn_entry *vpn_new(void){
 //printf("Create vpn instance .\n");
 vpn_entry *new= (vpn_entry *) malloc (sizeof( vpn_entry ));
 memset(new, 0, sizeof(vpn_entry));
 new->next=NULL;
 vpn_top=new;
 return new;
}
//more than one vpn entry to add new vpn entry into linklist.
vpn_entry *vpn_new_more(vpn_entry *vpn){	
	vpn_entry *new= (vpn_entry *) malloc (sizeof( vpn_entry ));
	memset(new, 0, sizeof(vpn_entry));
	new->next=vpn;
	vpn=new;
	vpn_top=new;
	return vpn;
}

vpn_entry *vpn_get() {
    if (vpn_top) {
	return vpn_top;
    }
    return NULL;
}

int vpn_finish(vpn_entry *vpn,int vpn_id){
	if(vpn==NULL)
	return -1;
	vpn_entry *this,*prev;
	this=vpn;
	if(this->vpn_id==vpn_id){
	//free first vpn node 
		vpn=this->next;
		vpn_top=vpn;
		free(this);
		return 0;	
	}else{
		prev=this;
		this=this->next;
		while(this!=NULL){
			if(this->vpn_id==vpn_id){
				prev->next=this->next;
				free(this);
				return 0;
			}
			prev=this;
			this=this->next;
		}
	}
	return -1;
}

//tunnel process
tunnel_entry *tunnel_new(void){
	//printf("Create tunnel instance (tunnel_new).\n");
 	tunnel_entry *new=(tunnel_entry *) malloc (sizeof(tunnel_entry));
 	memset(new,0,sizeof(tunnel_entry));
 	tunnel_top=new;
 	return new;
}

tunnel_entry *tunnel_new_more(tunnel_entry *tunnel){	
	printf("Create tunnel instance (tunnel_new_more).\n");
 	tunnel_entry *new=(tunnel_entry *) malloc (sizeof(tunnel_entry));
 	memset(new,0,sizeof(tunnel_entry));
 	new->next=tunnel;
 	tunnel=new;
 	tunnel_top=new;
 	return tunnel;
}

tunnel_entry *tunnel_finish(tunnel_entry *tunnel){
	tunnel_top=NULL;
	free(tunnel);
}

//success :1 ;fail : 0;
int del_tunnel_entry(tunnel_entry *tunnel,unsigned long dst_ip){
		tunnel_entry *this,*prev;
		this=tunnel;
		if(this->remote_ip.s_addr==dst_ip){
			//free first tunnel entry.
			tunnel_top=this->next;
			free(this);
			return 1;
		}else{
			prev=this;
			this=this->next;
			while(this!=NULL){
				if(this->remote_ip.s_addr==dst_ip){
					prev->next=this->next;
					free(this);
					return 1;
				}
				prev=this;
				this=this->next;
			}
		}
		return 0;
}

tunnel_entry *tunnel_get(void){
	if (tunnel_top) {
		return tunnel_top;
    	}
   	 	return NULL;
}
//end tunnel process

//start nic process
nic_info *nic_new(void){
	nic_info *new= (nic_info *) malloc (sizeof( nic_info ));
	memset(new,0,sizeof(nic_info));
	nic_top=new;
	return new;
}

nic_info *nic_get(void){
	if(nic_top){
		return nic_top;
  }
   	return NULL;
}
//end nic process
