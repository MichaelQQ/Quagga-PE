#include "vpnmd_rsvp_msg.h"
#include "vpnmd_table.h"
#include "vpnm_via_rsvp.h"
#include "vpnm_via_ldp.h"

#include "connect_daemon.h"

int add_in_tunnel_label(int label,char * in_if,unsigned long dst_ip,int lsp_id){
	//vpn_entry *vpn = vpn_get();
	tunnel_entry *tunnel=tunnel_get();
	tunnel_entry *top_tunnel;
	top_tunnel=tunnel;
	if(!tunnel){
		printf("There isn't an active VPN instance or tunnel instance.\n");
		return -1;
	}
	
	tunnel=search_tunnel_node(tunnel,dst_ip);
	if(!tunnel){
		top_tunnel=tunnel_new_more(top_tunnel);
		if(add_new_tunnel_entry(dst_ip,top_tunnel)){
   	  	printf("add_new_tunnel_entry fail.\n");
   	  	return -1;
   	}else{
   			top_tunnel->in_lsp_id=lsp_id;
   	  	top_tunnel->in_state = READY;
      	top_tunnel->in_tunnel_label = label;
				strcpy(top_tunnel->in_if,in_if);
				return 0;
   	}
	}else{
			tunnel->in_lsp_id=lsp_id;
			tunnel->in_state = READY;
      tunnel->in_tunnel_label =label;
			strcpy(tunnel->in_if,in_if);
			return 0;
	}//end if(!tunnel)
	 /*
		if(write_incoming_data_plane(vpn,dst_ip)){
			printf("write_incoming_data fail.\n");
		}else{
			printf("write_incoming_data sucess.\n");
		}//end if(write_incoming_data)
		*/
	return 0;
}

//not ready for use ; the next_hop_ip is not ready

//int add_out_tunnel_label(int label,char * out_if,unsigned long dst_ip,unsigned long next_hop_ip,int lsp_id){
int add_out_tunnel_label(int label,char * out_if,unsigned long dst_ip,
	unsigned long next_hop_ip,int nhlfe_key,int lsp_id){	
	//vpn_entry *vpn = vpn_get();
	tunnel_entry *tunnel=tunnel_get();
	tunnel_entry *top_tunnel;
	top_tunnel=tunnel;
	if(!tunnel){
		printf("There isn't an active tunnel instance.\n");
		return	-1;
	}
		tunnel=search_tunnel_node(tunnel,dst_ip);
		if(!tunnel){
			top_tunnel=tunnel_new_more(top_tunnel);
			if(add_new_tunnel_entry(dst_ip,top_tunnel)){
   	  	printf("add_new_tunnel_entry fail.\n");
   	  }else{
   	  	top_tunnel->out_lsp_id=lsp_id;
   	  	top_tunnel->out_state = READY;
				top_tunnel->out_tunnel_label = label;
				strcpy(top_tunnel->out_if, out_if);
				top_tunnel->next_hop_ip.s_addr=next_hop_ip;
				top_tunnel->nhlfe_key=nhlfe_key;
				return 0;
   	  }
			//printf("No get tunnel entry.\n");
		}else{
			tunnel->out_lsp_id=lsp_id;
			tunnel->out_state = READY;
			tunnel->out_tunnel_label = label;
			strcpy(tunnel->out_if, out_if);
			tunnel->next_hop_ip.s_addr=next_hop_ip;
			tunnel->nhlfe_key=nhlfe_key;
			return 0;
		}//end if(!tunnel)
		/*
		if(write_outgoing_data_plane(vpn,dst_ip)){
			printf("write_incoming_data fail.\n");
			//return;
		}else{
			printf("write_incoming_data sucess.\n");
		//	return;
		}//end if(write_incoming_data)
		*/
	return 0;
}

//sucess : 1 ; fail : 0;
int release_tunnel(int lsp_id,unsigned long dst_ip){
	tunnel_entry *tunnel=tunnel_get();
	tunnel_entry *top_tunnel;
	top_tunnel=tunnel;
	if(!tunnel){
		printf("There isn't an active tunnel instance.\n");
		return 0;
	}
	tunnel=search_tunnel_node(tunnel,dst_ip);
	if(!tunnel){
		printf("No tunnel entry is found.\n");
		return 0;
	}else{
		if(tunnel->in_lsp_id==lsp_id){
				tunnel->in_state=NOT_READY;//0
				tunnel->in_lsp_id=0;
				tunnel->in_tunnel_label=0;
				strcpy(tunnel->in_if, "");		
		}else if(tunnel->out_lsp_id==lsp_id){
				tunnel->out_state=NOT_READY;//0
				tunnel->out_lsp_id=0;
				tunnel->out_tunnel_label=0;
				strcpy(tunnel->out_if, "");
				tunnel->next_hop_ip.s_addr=inet_addr("0.0.0.0");
		}
		//printf("Debug msg(tunnel state ) in_state :%d\t out_state :%d",tunnel->in_state,tunnel->out_state);
		if(tunnel->in_state==NOT_READY && tunnel->out_state==NOT_READY){
			del_tunnel_entry(top_tunnel,tunnel->remote_ip.s_addr);
			printf("Delete tunnel entry .\n");
		}
	}
	return 1;
}

int pro_pathtear_msg(unsigned long dst_ip){
	vpn_entry *vpn = vpn_get();
	tunnel_entry *tunnel=tunnel_get();
//	tunnel_entry *top_tunnel;
//	top_tunnel=tunnel;
	if(!vpn || !tunnel){
		printf("There isn't an active VPN instance or tunnel instance.\n");
	}
		tunnel=search_tunnel_node(tunnel,dst_ip);
		if(!tunnel){
		//	printf("RSVP receives a PATHTEAR message from %s\nBut the tunnel between local to %s does not exist\n", inet_ntoa(dst_ip), inet_ntoa(dst_ip));
			return -1;
		}else{
			if(tunnel->in_state == NOT_READY){
			//	printf("RSVP receives a PATHTEAR message from %s\nBut the tunnel from %s to local does not exist\n", inet_ntoa(dst_ip), inet_ntoa(dst_ip));
				return 0;
			}else{
				tunnel->in_state = NOT_READY;
				tunnel->in_tunnel_label = 0;
				if(tunnel->out_state == NOT_READY){
					tunnel->in_use = UNUSED;
				}//end if(tunnel->out_state == NOT_READY)
				if(del_incoming_data_plane_here(vpn,dst_ip)){
					printf("del_incoming_data_plane fail.\n");
					return -1;
				}else{
					printf("del_incoming_data_plane sucess.\n");
					return 1;
				}//end if(del_incoming_data_plane(
			}//end if(tunnel->in_state == NOT_READY)
		}//end if(!tunnel)
		//	temp = find_tunnel_by_ip(vrx->u.rpi.remote_ip.s_addr);
		return 0;
}


int pro_resvtear_msg(unsigned long dst_ip){
	vpn_entry *vpn = vpn_get();
	tunnel_entry *tunnel=tunnel_get();
	//tunnel_entry *top_tunnel;
	//top_tunnel=tunnel;
	if(!vpn || !tunnel){
		printf("There isn't an active VPN instance or tunnel instance.\n");
	}
		tunnel=search_tunnel_node(tunnel,dst_ip);
		if(!tunnel){
			//printf("RSVP receives a RESVTEAR message from %s\nBut the tunnel between local to %s does not exist\n", inet_ntoa(vrx->u.rpi.remote_ip), inet_ntoa(vrx->u.rpi.remote_ip));
			return -1;
		}else{
			if(tunnel->out_state == NOT_READY){
				//printf("RSVP receives a RESVTEAR message from %s\nBut the tunnel from local to %s does not exist\n", inet_ntoa(vrx->u.rpi.remote_ip), inet_ntoa(vrx->u.rpi.remote_ip));
				return 0;
			}else{
				tunnel->out_state = NOT_READY;
				tunnel->out_tunnel_label = 0;
				if(tunnel->in_state == NOT_READY){
					tunnel->in_use = UNUSED;
				}
				if(del_outgoing_data_plane_here(vpn,dst_ip)){
					printf("del_outgoing_data_plane fail.\n");
					return -1;
				}else{
					printf("del_outgoing_data_plane sucess.\n");
					return 1;
				}//end if(del_outgoing_data_plane(
			}//end if(tunnel->out_state == NOT_READY)
		}//end if(!tunnel)
	return 0;
}

//delete data-plane information
int del_incoming_data_plane_here(vpn_entry *vpn,unsigned long ip){
	vpn_entry *vpn_this;
	pw_info_entry *pw;
	
	unsigned char temp_state;
	//vpn_ldp_xmsg vlx;

	if(vpn!=NULL){
		vpn_this=vpn;
		while(vpn_this->next!=NULL){
			if(vpn_this->in_use==USED){
				pw=get_pw_entry(vpn_this,ip);
				if(!pw){
					printf("quarry PW fail.\n");
				}else{
					if(pw->in_state != NOT_READY){
						temp_state = pw->in_state;
						if(pw->out_state==NOT_READY){
							del_pw_info(vpn,ip,-1);
						}else{
							pw->in_state = NOT_READY;
							pw->in_pw_label = 0;
						}//end if(pw->out_state==NOT_READY)
						if(temp_state== READY){
							printf("Delete vpn %d's incoming data plane forwarding information\n", vpn_this->vpn_id);
						}//end if(temp_state== READY)
					}//end if(pw->in_state != NOT_READY)
				}//end if(!pw)
			}//end if(vpn_this->in_use==USED)
			vpn_this=vpn_this->next;
		}//end while()
		//have only one vpn_entry not to check
		if(vpn_this->in_use==USED){
			pw=get_pw_entry(vpn_this,ip);
			if(!pw){
				printf("quarry PW fail.\n");
				return -1;
			}else{
				if(pw->in_state != NOT_READY){
					temp_state = pw->in_state;
					if(pw->out_state==NOT_READY){
						del_pw_info(vpn,ip,-1);
					}else{
						pw->in_state = NOT_READY;
						pw->in_pw_label = 0;
					}//end if(pw->out_state==NOT_READY)
					if(temp_state== READY){
						printf("Delete vpn %d's incoming data plane forwarding information\n", vpn_this->vpn_id);
					}//end if(temp_state== READY)
				}//end if(pw->in_state != NOT_READY)
				return 0;
			}//end if(!pw)
		}//end if(vpn_this->in_use==USED)
	}else{
   printf("NO vpn_entry .\n");
   return -1;
	}
	return 0;
}


int del_outgoing_data_plane_here(vpn_entry *vpn,unsigned long dst_ip){
	vpn_entry *vpn_this;
	pw_info_entry *pw;

	if(vpn!=NULL){
		vpn_this=vpn;
		while(vpn_this->next!=NULL){
			if(vpn_this->in_use==USED){
				pw=get_pw_entry(vpn_this,dst_ip);
				if(!pw){
					printf("quarry PW fail.\n");
				}else{
					if(pw->out_state != NOT_READY){
					 char buf[255];
 					 LDP_Command cmd;
		 			 cmd=ldpReleasePW;
 					 connect_daemon(VTYSH_INDEX_LDP);
 					 sprintf(buf,"cmd_type %d arg0 %d arg1 %d arg2 %d arg3 %s\n",cmd,0x05,vpn_this->vpn_id,pw->out_pw_label,dst_ip);
 					 vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LDP], buf, stdout);
					 exit_daemon(VTYSH_INDEX_LDP);
						if(pw->in_state == NOT_READY){
							del_pw_info(vpn,dst_ip,-1);
						}else{
							pw->out_state = NOT_READY;
							pw->out_pw_label = 0;
						}//end if(pw->in_state == NOT_READY)
						printf("Delete vpn %d's outgoing data plane forwarding information\n", vpn_this->vpn_id);
					}//end if(pw->out_state != NOT_READY)
				}//end if(!pw)
			}//end if(vpn_this->in_use==USED)
			vpn_this=vpn_this->next;
		}//end while()
		//have only one vpn_entry not to check
		if(vpn_this->in_use==USED){
			pw=get_pw_entry(vpn_this,dst_ip);
			if(!pw){
				printf("quarry PW fail.\n");
				return -1;
			}else{
				if(pw->out_state != NOT_READY){
					char buf[255];
 					LDP_Command cmd;
		 			cmd=ldpReleasePW;
 					connect_daemon(VTYSH_INDEX_LDP);
 					sprintf(buf,"cmd_type %d arg0 %d arg1 %d arg2 %d arg3 %s\n",cmd,0x05,vpn_this->vpn_id,pw->out_pw_label,dst_ip);
 					vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LDP], buf, stdout);
					exit_daemon(VTYSH_INDEX_LDP);
					if(pw->in_state == NOT_READY){
						del_pw_info(vpn,dst_ip,-1);
					}else{
						pw->out_state = NOT_READY;
						pw->out_pw_label = 0;
					}//end if(pw->out_state==NOT_READY)		
					printf("Delete vpn %d's outgoing data plane forwarding information\n", vpn_this->vpn_id);
				}//end if(pw->out_state != NOT_READY)
				return 0;
			}//end if(!pw)
		}//end if(vpn_this->in_use==USED)
	}else{
  	printf("NO vpn_entry .\n");
  	return -1;
	}
	return 0;
}
