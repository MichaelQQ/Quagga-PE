#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "vpnmd_table.h"

//0 :success -1: fail
int show_vpls_info(struct vty *vty,vpn_entry *vpn,tunnel_entry *tunnel){
	char buffer[20];
	printf("-------------show_vpls_info------------------\n");
	//tunnel_entry *tunnel=tunnel_get();
	tunnel_entry *tunnel_this;
	struct vpn_entry *vpn_this;
	struct pw_info_entry *pw_this;
	char buf[1000];//sprintf(); will be caused Segmentation fault.Buffer size to small;
	//printf("------  SHOW VPLS Instance PW information -------\n");
	//printf("vpn entry :%d\n",vpn);
	if(vpn !=NULL){
		vpn_this=vpn;
		do{
			sprintf(buf," vpn id : %d  vpn state : %d%s",vpn_this->vpn_id,vpn_this->in_use,VTY_NEWLINE);
			printf("vpn id : %d\n",vpn_this->vpn_id);
			printf("vpn state : %d\n",vpn_this->in_use);
			//print vpls port id information
			if(vpn_this->pw_info_ptr!=NULL){
				pw_this=vpn_this->pw_info_ptr;
				do{
					//Display the tunnel information
					tunnel_this=search_tunnel_node(tunnel,pw_this->remote_ip.s_addr);
					if(tunnel_this){
						sprintf(buffer,"%s",inet_ntoa(tunnel_this->next_hop_ip));
						printf("***********************************\n");
						printf("remote_ip: %s\t in_use : %d\n",inet_ntoa(tunnel_this->remote_ip),tunnel_this->in_use);
						printf("in_label :%d in_if:%s lsp_id:%d\n",tunnel_this->in_tunnel_label,tunnel_this->in_if,tunnel_this->in_lsp_id);
						printf("out_label:%d out_if:%s next_hop_ip:%s lsp_id:%d\n",tunnel_this->out_tunnel_label,tunnel_this->out_if,buffer,tunnel_this->out_lsp_id);
						printf("***********************************\n");
						sprintf(buf,"%s in_use :%d\t remote_ip :%s%s lsp_id :%d\t in_if:%s\t in_label:%d%s lsp_id :%d\t out_if:%s\t out_label:%d\t next_hop_ip:%s%s",buf,tunnel_this->in_use,inet_ntoa(tunnel_this->remote_ip),VTY_NEWLINE,tunnel_this->in_lsp_id,tunnel_this->in_if,tunnel_this->in_tunnel_label,VTY_NEWLINE,tunnel_this->out_lsp_id,tunnel_this->out_if,tunnel_this->out_tunnel_label,buffer,VTY_NEWLINE);
					}
					//end  display
					printf("remote_ip :%s\n",inet_ntoa(pw_this->remote_ip));
					printf("IN_STATE:%d\t IN_LABEL:%d\n",pw_this->in_state,pw_this->in_pw_label);
					printf("OUT_STATE:%d\t OUT_LABEL:%d\n",pw_this->out_state,pw_this->out_pw_label);
					sprintf(buf,"%s IN_STATE :%d\t IN_PW_LABLE:%d%s OUT_STATE:%d\t OUT_PW_LABEL:%d%s",buf,pw_this->in_state,pw_this->in_pw_label,VTY_NEWLINE,pw_this->out_state,pw_this->out_pw_label,VTY_NEWLINE);
					pw_this=pw_this->next;
				}while(pw_this!=NULL);
			}
	    //end print vpls pw information
	    vty_out(vty,"%s",buf);
			vpn_this=vpn_this->next;
		}while(vpn_this!=NULL);
		printf("-----------END-------------------\n");
	  return 0;
	}else{
		return -1; // no any vpn entry;
	}
}

//0 :success -1: fail
int show_tunnel_info(struct vty *vty,tunnel_entry *tunnel){
	char buffer[20];
	char buf[1000]={0};//sprintf(); will be caused Segmentation fault.Buffer size to small;
	printf("------show_tunnel_info---------------\n");
	tunnel_entry *tunnel_this;
	if(tunnel!=NULL){
		tunnel_this=tunnel;
		do{
			sprintf(buffer,"%s",inet_ntoa(tunnel_this->next_hop_ip));
			printf("***********************************\n");
			printf("remote_ip: %s\t in_use : %d\n",inet_ntoa(tunnel_this->remote_ip),tunnel_this->in_use);
			printf("in_label :%d in_if:%s lsp_id:%d\n",tunnel_this->in_tunnel_label,tunnel_this->in_if,tunnel_this->in_lsp_id);
			printf("out_label:%d out_if:%s next_hop_ip:%s lsp_id:%d\n",tunnel_this->out_tunnel_label,tunnel_this->out_if,buffer,tunnel_this->out_lsp_id);
			printf("***********************************\n");
			//sprintf(buf,"%s in_use :%d\t remote_ip :%s%s in_label :%d\t in_if:%s\t lsp_id:%d%s out_label:%d\t out_if:%s\t next_hop_ip:%s\t lsp_id:%d%s",buf,tunnel_this->in_use,inet_ntoa(tunnel_this->remote_ip),VTY_NEWLINE,tunnel_this->in_tunnel_label,tunnel_this->in_if,tunnel_this->in_lsp_id,VTY_NEWLINE,tunnel_this->out_tunnel_label,tunnel_this->out_if,buffer,tunnel_this->out_lsp_id,VTY_NEWLINE);
			sprintf(buf,"%s in_use :%d\t remote_ip :%s%s lsp_id :%d\t in_if:%s\t in_label:%d%s lsp_id :%d\t out_if:%s\t out_label:%d\t next_hop_ip:%s%s",buf,tunnel_this->in_use,inet_ntoa(tunnel_this->remote_ip),VTY_NEWLINE,tunnel_this->in_lsp_id,tunnel_this->in_if,tunnel_this->in_tunnel_label,VTY_NEWLINE,tunnel_this->out_lsp_id,tunnel_this->out_if,tunnel_this->out_tunnel_label,buffer,VTY_NEWLINE);
			tunnel_this=tunnel_this->next;
		}while(tunnel_this!=NULL);
	}else{
		printf("NO TUNNEL entry is used.\n");
		vty_out(vty,"No tunnel information is recorded.%s",VTY_NEWLINE);
		return -1;
	}
	printf("-------------------------------------\n");
	vty_out(vty,"%s",buf);
	return 0;
}

//process PW function
pw_info_entry *fetch_pw_by_ip(vpn_entry *vpn,unsigned long ip){
	pw_info_entry *this;
  vpn_entry *vpn_this;
	
	if (vpn->pw_info_ptr != NULL){
		this = vpn->pw_info_ptr;
		while (this->next != NULL){
			if (this->remote_ip.s_addr == ip){
				return this;
			}
			this = this->next;
		}
		if (this->remote_ip.s_addr == ip)
		{
			return this;
		}
		return NULL;
	}
	return NULL; //not match
}
//end process PW function

int show_pw_info(struct vty *vty,vpn_entry *vpn){
	struct vpn_entry *vpn_this;
	struct pw_info_entry *pw_this;
	char buf[1000];//sprintf(); will be caused Segmentation fault.Buffer size to small;
	printf("------  SHOW VPLS Instance PW information -------\n");
	//printf("vpn entry :%d\n",vpn);
	if(vpn !=NULL){
		vpn_this=vpn;
		do{
			printf("************************\n");
			sprintf(buf,"vpn id : %d  vpn state : %d%s",vpn_this->vpn_id,vpn_this->in_use,VTY_NEWLINE);
			printf("vpn id : %d\n",vpn_this->vpn_id);
			printf("vpn state : %d\n",vpn_this->in_use);
			//print vpls port id information
			if(vpn_this->pw_info_ptr!=NULL){
				pw_this=vpn_this->pw_info_ptr;
				do{
					printf("remote_ip :%s\n",inet_ntoa(pw_this->remote_ip));
					printf("IN_STATE:%d\t IN_LABEL:%d\n",pw_this->in_state,pw_this->in_pw_label);
					printf("OUT_STATE:%d\t OUT_LABEL:%d\n",pw_this->out_state,pw_this->out_pw_label);
					sprintf(buf,"%s remote_ip :%s%s IN_STATE :%d\t  IN_LABLE:%d%s OUT_STATE:%d\t OUT_LABEL:%d%s",buf,inet_ntoa(pw_this->remote_ip),VTY_NEWLINE,pw_this->in_state,pw_this->in_pw_label,VTY_NEWLINE,pw_this->out_state,pw_this->out_pw_label,VTY_NEWLINE);
					pw_this=pw_this->next;
				}while(pw_this!=NULL);	
			}
	    //end print vpls pw information
	    vty_out(vty,"%s",buf);
			vpn_this=vpn_this->next;
		}while(vpn_this!=NULL);
		printf("-----------END-------------------\n");
	  return 0;
	}else{
		return -1; // no any vpn entry;
	}
}

void show_port_info(port_id_entry *port){
	while(port!=NULL){
		printf("customer-facing poort:%s\n",port->iface);
		port=port->next;
	}
}
