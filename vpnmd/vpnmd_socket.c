#include "vpnmd_ldp_msg.h"
#include "vpnmd_rsvp_msg.h"
#include "vpnmd_table.h"

#define WITHDRAW_DOIT -1

//temp date-plane function
int write_incoming_data_plane(vpn_entry *vpn,unsigned long ip){
	vpn_entry *vpn_this;
	pw_info_entry *pw;

	if(vpn!=NULL){
		vpn_this=vpn;
		while(vpn_this->next!=NULL){
			if(vpn_this->in_use==USED){
				pw=get_pw_entry(vpn_this,ip);
				if(!pw){
					printf("quarry PW fail.\n");
				}else{
					if(pw->in_state == READY)
						printf("Add vpn %d's incoming data plane forwarding information\n", vpn_this->vpn_id);
				}
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
				if(pw->in_state == READY)
					printf("Add vpn %d's incoming data plane forwarding information\n", vpn_this->vpn_id);
				return 0;
			}
		}//end if(vpn_this->in_use==USED)
	}else{
   printf("NO vpn_entry .\n");
   return -1;
	}
	return 0;
}

int write_outgoing_data_plane(vpn_entry *vpn,unsigned long ip){

	vpn_entry *vpn_this;
	pw_info_entry *pw;

	if(vpn!=NULL){
		vpn_this=vpn;
		while(vpn_this->next!=NULL){
			if(vpn_this->in_use==USED){
				pw=get_pw_entry(vpn_this,ip);
				if(!pw){
					printf("quarry PW fail.\n");
				}else{
					if(pw->out_state == READY)
						printf("Add vpn %d's outgoing data plane forwarding information\n",vpn_this->vpn_id);
				}
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
				if(pw->out_state == READY)
					printf("Add vpn %d's incoming data plane forwarding information\n", vpn_this->vpn_id);
				return 0;
			}
		}//end if(vpn_this->in_use==USED)
	}else{
   printf("NO vpn_entry .\n");
   return -1;
	}
	return 0;
}

//delete data-plane information
/*
int del_incoming_data_plane(int fd,vpn_entry *vpn,unsigned long ip){
	vpn_entry *vpn_this;
	pw_info_entry *pw;
	
	unsigned char temp_state;
	vpn_ldp_xmsg vlx;

	if(vpn!=NULL){
		vpn_this=vpn;
		while(vpn_this->next!=NULL){
			if(vpn_this->in_use==USED){
				pw=get_pw_entry(vpn_this,ip);
				if(!pw){
					printf("quarry PW fail.\n");
				}else{
					if(pw->in_state != NOT_READY){
						vlx.mid = VPN_M_MOD_ID;
						vlx.type = WITHDRAW_PW;
						vlx.u.vi.vc_type = 0x05;
						vlx.u.vi.vpn_id = vpn_this->vpn_id;
						vlx.u.vi.label = pw->in_pw_label;
						vlx.u.vi.remote_ip.s_addr = ip;
						if(send_msg_to_other_process(fd, LDP_PORT, &vlx, sizeof(vlx))==-1){
							printf("send_msg_to_other_process fail.\n");
							return -1;
						}
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
					vlx.mid = VPN_M_MOD_ID;
					vlx.type = WITHDRAW_PW;
					vlx.u.vi.vc_type = 0x05;
					vlx.u.vi.vpn_id = vpn_this->vpn_id;
					vlx.u.vi.label = pw->in_pw_label;
					vlx.u.vi.remote_ip.s_addr = ip;
					if(send_msg_to_other_process(fd, LDP_PORT, &vlx, sizeof(vlx))==-1){
						printf("send_msg_to_other_process fail.\n");
						return -1;
					}
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

int del_outgoing_data_plane(int fd,vpn_entry *vpn,unsigned long ip){
	vpn_entry *vpn_this;
	pw_info_entry *pw;
	
	unsigned char temp_state;
	vpn_ldp_xmsg vlx;

	if(vpn!=NULL){
		vpn_this=vpn;
		while(vpn_this->next!=NULL){
			if(vpn_this->in_use==USED){
				pw=get_pw_entry(vpn_this,ip);
				if(!pw){
					printf("quarry PW fail.\n");
				}else{
					if(pw->out_state != NOT_READY){
						vlx.mid = VPN_M_MOD_ID;
						vlx.type = RELEASE_PW;
						vlx.u.vi.vc_type = 0x05;
						vlx.u.vi.vpn_id = vpn_this->vpn_id;
						vlx.u.vi.label = pw->out_pw_label;
						vlx.u.vi.remote_ip.s_addr = ip;
						if(send_msg_to_other_process(fd, LDP_PORT, &vlx, sizeof(vlx))==-1){
							printf("send_msg_to_other_process fail.\n");
							return -1;
						}
						if(pw->in_state == NOT_READY){
							del_pw_info(vpn,ip,-1);
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
			pw=get_pw_entry(vpn_this,ip);
			if(!pw){
				printf("quarry PW fail.\n");
				return -1;
			}else{
				if(pw->out_state != NOT_READY){
					vlx.mid = VPN_M_MOD_ID;
					vlx.type = RELEASE_PW;
					vlx.u.vi.vc_type = 0x05;
					vlx.u.vi.vpn_id = vpn_this->vpn_id;
					vlx.u.vi.label = pw->out_pw_label;
					vlx.u.vi.remote_ip.s_addr = ip;
					if(send_msg_to_other_process(fd, LDP_PORT, &vlx, sizeof(vlx))==-1){
						printf("send_msg_to_other_process fail.\n");
						return -1;
					}
					if(pw->in_state == NOT_READY){
						del_pw_info(vpn,ip,-1);
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
*/

//end temp date-plane function