#include "vpnmd_ldp_msg.h"
#include "vpnmd_rsvp_msg.h"
#include "vpnm.h"
#include "vpnm_via_ldp.h"
#include "vpnm_via_mpls.h"
#include "vpnm_via_brctl.h"

int set_in_pw_info(struct vty *vty,int vpn_id,unsigned long dst_ip,int label){
  
  char pw_if[20]={0};
  char br_name[20]={0};
	pw_info_entry *pw;
	vpn_entry *vpn = vpn_get();
	
	if(!vpn ){
		printf("There isn't an active VPN instance .\n");
		return -1;
	}
	vpn=search_vpn_node(vpn,vpn_id);
	if(!vpn){
			printf("please firest set vpn_id :%d\n",vpn_id);
			return -1;
		}//end if(!vpn)
	pw=get_pw_entry(vpn,dst_ip);
	if(!pw){
		printf("Get PW entry fail.\n");
		setup_pw_info(vpn,dst_ip,0);
		pw=get_pw_entry(vpn,dst_ip);
		//return -1;
	}
	pw->in_state = READY;
	pw->in_pw_label = label;/*
	if(pw->out_state==NOT_READY){
		sprintf(pw_if,"mpls%d\0",label);
		strcpy(pw->iface,pw_if);
	}*/
	sprintf(pw_if,"mpls%d",vpn_id);
	strcpy(pw->iface,pw_if);
	printf("ckeck the tunnel state .\n");
	tunnel_entry *tunnel=tunnel_get();
	struct in_addr tmp_addr;
	nic_info *nic;
	nic=nic_get();
	int retval=0;
	if(!tunnel){
		printf("There isn't an active tunnel instance.\n");
		//tigger VPN Manager to setup Tunnel 
		tmp_addr.s_addr=dst_ip;
		retval=setup_tunnel(vty,nic->ip,inet_ntoa(tmp_addr),nic->lsp_id);
		if(retval>0) 
			return retval;
		else
			return retval;
		//return -1;
	}
	tunnel=search_tunnel_node(tunnel,dst_ip);
	if(!tunnel){
		//struct in_addr tmp_addr;
		//tigger VPN Manager to setup Tunnel 
		tmp_addr.s_addr=dst_ip;
		retval=setup_tunnel(vty,nic->ip,inet_ntoa(tmp_addr),nic->lsp_id);
		if(retval>0) 
			return retval;
		else
			return retval;
	}else{
		//write data-plane processing code
		if(tunnel->in_state== READY){
			printf("DEBUG(VPN Manager):begin to write nhlfe entry. (set_in_vclsp)\n");
			//int set_in_vclsp(const char *pw_if,int ilabel)
			set_in_vclsp(pw->iface,pw->in_pw_label,pw->out_state);
			printf("DEBUG(VPN Manager):Finished to write nhlfe entry. (set_in_vclsp)\n");
			printf("vpn_id:%d\tpw->iface:%s\n",vpn_id,pw->iface);
			sprintf(br_name,"br%d",vpn_id);
			add_if(br_name,pw->iface);
			return 0;
		}else{
			printf("MPLS Out Tunnel LSP NOT_READY.\n");
			return -1;
		} 
		/*
		if(tunnel->in_state == READY){
			printf("Add vpn %d's incoming data plane forwarding information\n",vpn_id);
			return 1;//seccess
		}else if(tunnel->in_state == PROCESSING){
			printf("The PW's tunnel is being established\nPlease wait a minute\n");
			return 0;//waitting 
		}else{
			printf("There is no tunnel that can be used by this PW\nPlease trigger remote PE to establish tunnel for use\n");
			return -1;
		}*/
	}//end if(!tunnel)
}

int set_out_pw_info(int vpn_id,unsigned long dst_ip,int label){
	
	char pw_if[20]={0};
	pw_info_entry *pw;
	vpn_entry *vpn = vpn_get();
	if(!vpn){
		printf("There isn't an active VPN instance.\n");
		return -1;
	}
	printf("DEBUG(VPN Manager):set_out_pw_info enter.\n");
	//need to check get vpn entry those code is need to write again.
	vpn=search_vpn_node(vpn,vpn_id);
	if(!vpn){
		printf("please firest set vpn_id :%d\n",vpn_id);
		return -1;
	}//end if(!vpn)
	vpn->in_use=USED;
	pw=get_pw_entry(vpn,dst_ip);
	if(!pw){
		printf("Get PW entry fail.\n");
		setup_pw_info(vpn,dst_ip,2);
		pw=get_pw_entry(vpn,dst_ip);
		//return -1;
	}
	pw->out_state = READY;
	pw->out_pw_label = label;
	/*
	if(pw->in_state==NOT_READY){
		sprintf(pw_if,"mpls%d\0",label);
		strcpy(pw->iface,pw_if);
	}*/
	sprintf(pw_if,"mpls%d",vpn_id);
	strcpy(pw->iface,pw_if);
	printf("DEBUG(VPN Manager) Pseudo-Wires :%d\t iface :%s\n",pw->out_pw_label,pw->iface);
	/*
	vpn->in_use=USED;
	//add the new pw node 
	if(setup_pw_info(vpn,dst_ip,2)){
		printf("Fail to setup_pw_info .\n");
		return -1;
	}else{
		//set the pw informations
		vpn->pw_info_ptr->out_state = READY;
		vpn->pw_info_ptr->out_pw_label = label;
		if(vpn->pw_info_ptr->in_state ==NOT_READY){
			//if in_state ==NOT_READY the mapping  PW interface == mpls_vpnid
			sprintf(pw_if,"mpls%d",vpn_id);
			strcpy(vpn->pw_info_ptr->iface,pw_if);
		}
		//vpn->pw_info_ptr->iface
		return 1; //need to check this return ????
	}*/
	//need to check get tunnel entry those code is need to write again.
  printf("Start and check the tunnel entry is set or not ready.\n");
  //Don't to setup tunnel ;  
	tunnel_entry *tunnel=tunnel_get();
	if(!tunnel){
		printf("There isn't an active VPN instance or tunnel instance.\n");
		return -1;
	}
	
	tunnel=search_tunnel_node(tunnel,dst_ip);
	if(!tunnel){
		//printf("please firest set remote_ip :%s\n",inet_ntoa(vlx->u.pli.remote_ip));
		//printf("LDP receives a label mapping message from %s\nBut there is no tunnel that can be used by this PW\nPlease use the command \"setup_tunnel\" to establish a tunnel\n", inet_ntoa(vlx->u.pli.remote_ip));
		return -1;
	}else{
		if(tunnel->out_state == READY){
			printf("DEBUG(VPN Manager):begin to write nhlfe entry. (set_out_vclsp) out_state =READY\n");
			//int set_out_vclsp(const char *pw_if,int olabel,int nhlfe_key,int pw_in_state)
			//set_out_vclsp(vpn->pw_info_ptr->iface,label,tunnel->nhlfe_key,vpn->pw_info_ptr->in_state);
			set_out_vclsp(pw->iface,label,tunnel->nhlfe_key,pw->in_state);
			//printf("Add vpn %d's outgoing data plane forwarding information\n", vpn_id);
      printf("DEBUG(VPN Manager):finished. (set_out_vclsp)");
      return 1;
		}else if(tunnel->out_state == PROCESSING){
			printf("DEBUG(VPN Manager):Tunnel out_state =PROCESSING\n");
      //printf("LDP receives a label mapping message from %s\nAnd the PW's tunnel is being established\nPlease wait a minute\n", inet_ntoa(vlx->u.pli.remote_ip));
      return 0;
    }else{
    	printf("DEBUG(VPN Manager):Tunnel out_state =NOT_READY\n");
			//printf("LDP receives a label mapping message from %s\nBut there is no tunnel that can be used by this PW\nPlease use the command \"setup_tunnel\" to establish a tunnel\n", inet_ntoa(vlx->u.pli.remote_ip));
			return -1;
		}//end if(tunnel->out_state == READY)
	}//end if(!tunnel)
	
}

int withdraw_pw_info(int vpn_id,unsigned long dst_ip){
	pw_info_entry *pw;
	vpn_entry *vpn = vpn_get();
	
	if(!vpn ){
		printf("There isn't an active VPN instance .\n");
		return -1;
	}
	//need to check get vpn entry those code is need to write again.
	vpn=search_vpn_node(vpn,vpn_id);
	if(!vpn){
		printf("please firest set vpn_id :%d\n",vpn_id);
		return -1;
	}//end if(!vpn)
	if(vpn->in_use==UNUSED){
			//printf("LDP receives a withdraw message from %s\nBut this VPN_ID carried in the message have not be use\n", inet_ntoa(vlx->u.wpm.remote_ip));
			return -1;
		}else{
			pw=get_pw_entry(vpn,dst_ip);
			if(!pw){
				//printf("LDP receive a withdraw message from %s\nBut the PW between local to %s does not exist\n", inet_ntoa(vlx->u.wpm.remote_ip), inet_ntoa(vlx->u.wpm.remote_ip));
				return -1;
			}else{
				if (pw->out_state == NOT_READY){
					//printf("LDP receive a withdraw message from %s\nBut the PW from local to %s does not exist\n", inet_ntoa(vlx->u.wpm.remote_ip), inet_ntoa(vlx->u.wpm.remote_ip));
					return -1;
				}else{ 
					//do not process out_state == PROCESSING, because the
					//out_state is controlled by peer LDP. When LDP receives
					//label mapping message sent by peer LDP, the out_state
					//will be set with READY. Otherwise, it will be set with
					//NOT_READY, so the state PROCESSING won't appear.
					if(pw->in_state == NOT_READY){
						del_pw_info(vpn,dst_ip,WITHDRAW_DOIT);
					}else{
						pw->out_state = NOT_READY;
						pw->out_pw_label = 0;
					}//end if(pw->in_state..
					tunnel_entry *tunnel=tunnel_get();
					if(!tunnel ){
						printf("There isn't an active tunnel instance instance.\n");
						return -1;
					}
					tunnel=search_tunnel_node(tunnel,dst_ip);
					if(!tunnel){
					//printf("please firest set remote_ip :%s\n",inet_ntoa(vlx->u.pli.remote_ip));
					//printf("LDP receives a label mapping message from %s\nBut there is no tunnel that can be used by this PW\nPlease use the command \"setup_tunnel\" to establish a tunnel\n", inet_ntoa(vlx->u.pli.remote_ip));
					return -1;
					}else{
						if(tunnel->in_use==USED&&tunnel->out_state == READY){
							printf("Delete vpn %d's outgoing data plane forwarding information\n",vpn_id);
							return 1;
						}else{
							printf("Tunnel->in_use==UNUSED. Not deletet vpn data plane forwarding information.\n");
							return 0;
						}//end if(tunnel->in_use...
					}//end if(!tunnel)
				}//end if(pw->out_state == NOT_READY)
			}//end if(!pw)
		}//end if(vpn->in_use==UNUSED)
}
int release_pw_info(int vpn_id,unsigned long dst_ip){
	unsigned char temp_state;
	pw_info_entry *pw;
	vpn_entry *vpn = vpn_get();
	
	if(!vpn ){
		printf("There isn't an active VPN instance .\n");
		return -1;
	}
	//need to check get vpn entry those code is need to write again.
	vpn=search_vpn_node(vpn,vpn_id);
	if(!vpn){
		printf("please firest set vpn_id :%d\n",vpn_id);
		return -1;
	}//end if(!vpn)
	if(vpn->in_use==UNUSED){
			//printf("LDP receives a release message from %s\nBut this VPN_ID carried in the message have not be use\n", inet_ntoa(vlx->u.wpm.remote_ip));
      return -1;
		}else{
			pw=get_pw_entry(vpn,dst_ip);
			if(!pw){
				//printf("LDP receive a release message from %s\nBut the PW between local to %s does not exist\n", inet_ntoa(vlx->u.wpm.remote_ip), inet_ntoa(vlx->u.wpm.remote_ip));
				return -1;
			}else{
				if(pw->in_state == NOT_READY){
					//printf("LDP receive a release message from %s\nBut the PW from %s to local does not exist\n", inet_ntoa(vlx->u.wpm.remote_ip), inet_ntoa(vlx->u.wpm.remote_ip));
          return -1;
				}else{
					temp_state = pw->in_state;
					if(pw->out_state == NOT_READY){
						del_pw_info(vpn,dst_ip,WITHDRAW_DOIT);
					}else{
						 pw->in_state = NOT_READY;
             pw->in_pw_label = 0;
					}//end if(pw->out_state == NOT_READY)
					if(temp_state == READY){
						tunnel_entry *tunnel=tunnel_get();
						if(!tunnel ){
							printf("There isn't an active tunnel instance instance.\n");
							return -1;
						}
						tunnel=search_tunnel_node(tunnel,dst_ip);
						if(!tunnel){
							//printf("please firest set remote_ip :%s\n",inet_ntoa(vlx->u.wpm.remote_ip));
							return -1;
						}else{
							if(tunnel->in_use==USED &&tunnel->in_state == READY){
								printf("Delete vpn %d's incoming data plane forwarding information\n", vpn_id);
							}
						}
					}//end if(temp_state == READY)
					return 1;
				}//end if(pwe->in_state == NOT_READY)				
			}//end if(!pw)
		}
}

int setup_pw_info_here(struct vty *vty,int vpn_id,unsigned long dst_ip,int pw_in_label){

	vpn_entry *vpn = vpn_get();
	if(!vpn){
		printf("There isn't an active VPN instance .Please create a new vpls instance.\n");
		return -1;
	}
	//need to check get vpn entry those code is need to write again.
	vpn=search_vpn_node(vpn,vpn_id);
	if(!vpn){
		printf("This vpn_id : %d doesn't set before.\n",vpn_id);
	}
	if(pw_in_label>0){
		setup_pw_info(vpn,dst_ip,0);
		set_in_pw_info(vty,vpn_id,dst_ip,pw_in_label);
	}else{
		printf("Please reset the setup_pw command.\n");
	}

}
