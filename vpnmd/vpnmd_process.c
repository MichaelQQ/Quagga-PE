#include "vpnmd_process.h"
#include "vpnmd_rsvp_msg.h"
#include "connect_daemon.h"
#include "vpnm_via_rsvp.h"
#include "vpnm_via_brctl.h"

//vpn_entry process function block
//serarch vpn_entry by vpn_id  return vpn_entry address pointer
vpn_entry *search_vpn_node(vpn_entry * vpn,int vpn_id){
	vpn_entry *this;
	this=vpn;
	if(this->next!=NULL){
		do{
		if(this->vpn_id==vpn_id)
			return this; 
		this=this->next;
		}while(this!=NULL);
	}else{
		if(this->vpn_id==vpn_id)
			return this;
		else
			return NULL;
	}
	return NULL;
}

//0 : sucesses -1 : fail
int qurray_vpn_entry(struct vty *vty,vpn_entry * vpn,int vpn_id){
	char message[50];
	sprintf(message,"The vpn id : %d is already exit, please set other vpn_id number\n",vpn_id);
	vpn_entry *this;
	this=vpn;
	while(this->next!=NULL){
		if(this->vpn_id==vpn_id){
			vty_out(vty,message);
			return 0;
		}
		this=this->next;	
	}
	if(this->vpn_id==vpn_id){
		vty_out(vty,message);
		return 0;	
	}else{
		return -1 ;
	}
	return -1;
}

//rewrite add_port_info to set customer-facing port informations
int set_customer_facig_port(int vpn_id, const char *ifname){
	char br_name[10]={0};
	port_id_entry *new_node;
	vpn_entry *vpn = vpn_get();
 	if (!vpn)
 		return -1;
 		
 	vpn=search_vpn_node(vpn,vpn_id);
 	if(!vpn)
 		return -1;
 	
	new_node = (port_id_entry *) malloc(sizeof(port_id_entry));
	
	if (!new_node)
		return -1;
	//initial new_node
	memset(new_node,0,sizeof(struct port_id_entry));
	
	strcpy(new_node->iface,ifname);
	sprintf(br_name,"br%d",vpn_id);
	if(add_if(br_name,ifname)!=0)
		return -1;
	if (vpn->in_use==USED){
		if(vpn->port_id_ptr == NULL){
			vpn->port_id_ptr=new_node;
		}else{
			new_node->next=vpn->port_id_ptr;
			vpn->port_id_ptr=new_node;
		}
		show_port_info(vpn->port_id_ptr);//testing ;
		return 0; //set port id info ok;
	}else
		return -1;
}

//rewrite del_port to delete customer-facing port informations
int delete_customer_facig_port(int vpn_id, const char *ifname){
	char br_name[10]={0};
	port_id_entry *this, *prev;//, *free_node;
	vpn_entry *vpn = vpn_get();
 	if (!vpn)
 		return -1;
 		
 	vpn=search_vpn_node(vpn,vpn_id);
 	if(!vpn)
 		return -1;
 		
 	if(vpn->port_id_ptr==NULL)
		return -1;
	
	this=vpn->port_id_ptr;
	if(strcmp(this->iface,ifname)){
		//free first vpn node
		vpn->port_id_ptr=this->next;
		free(this);
		sprintf(br_name,"br%d",vpn_id);
		if(del_if(br_name,ifname)!=0)
			return -1;
		show_port_info(vpn->port_id_ptr);//testing ;
		return 0;
	}else{
		prev=this;
		this=this->next;
		while(this!=NULL){
			if(strcmp(this->iface,ifname)){
				prev->next=this->next;
				free(this);
				sprintf(br_name,"br%d",vpn_id);
				if(del_if(br_name,ifname)!=0)
					return -1;
				show_port_info(vpn->port_id_ptr);//testing ;
				return 0;
			}
			prev=this;
			this=this->next;
		}
	}
	return -1;	
}

//-1: malloc fail, 0: the vpn_entry is not in work, 1: success
int add_port_info (struct vty *vty,vpn_entry * vpn, int port_id)
{
	port_id_entry *new_node;

	new_node = (port_id_entry *) malloc(sizeof(port_id_entry));
	if (new_node == NULL){
		return -1;
	}
	new_node->next = NULL;
	new_node->port_id=0;
	new_node->port_id = port_id;
	if (vpn->in_use==USED){
		if(vpn->port_id_ptr == NULL){
			vpn->port_id_ptr=new_node;
		}else{
			new_node->next=vpn->port_id_ptr;
			vpn->port_id_ptr=new_node;
		}
		return 1; //set port id info ok;
	}else{
		vty_out(vty,"Please add_vpls_id vpn_id xx cmd first.\n");
		return 0;
	}
}
//No port_id-matching is not allowed in this function, so there is no returned value.
//In other words, you must make sure that the port_id will be found in this vpn_tab entry.
// 0: success; -1 : fail;
int del_port (vpn_entry *vpn, int port_id)
{ 
	if(vpn->port_id_ptr==NULL)
	return -1;
	port_id_entry *this, *prev;//, *free_node;
	this=vpn->port_id_ptr;
	if(this->port_id==port_id){
		//free first vpn node
		vpn->port_id_ptr=this->next;
		free(this);
		return 0;
	}else{
		prev=this;
		this=this->next;
		while(this!=NULL){
			if(this->port_id==port_id){
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
int del_vpn_info(vpn_entry *vpn,int vpn_id){
	if(vpn==NULL)
	return -1;
	vpn_entry *this, *vpn_top;
	vpn_top=vpn;
	//port_id_entry *free_node;
	this=search_vpn_node(vpn,vpn_id);
	while(this->port_id_ptr!=NULL){
		printf("del port :%d\n",this->port_id_ptr->port_id);
		del_port(this,this->port_id_ptr->port_id);
	}
	printf("free vpn_id :%d\n",this->vpn_id);
	if(!vpn_finish(vpn_top,this->vpn_id))
		return 0;
	else
		return -1;
	
}

//not finish function 
int del_pw_info(vpn_entry *vpn,unsigned long ip,int state){

	if(vpn->pw_info_ptr==NULL)
		return -1;
	pw_info_entry *this,*prev;
	this=vpn->pw_info_ptr;
	if(this->remote_ip.s_addr==ip && (this->in_state==READY && state==WITHDRAW_IN) ||(this->out_state==READY && state==WITHDRAW_OUT) || (state==WITHDRAW_DOIT) ){
		//free first PW entry
		vpn->pw_info_ptr=this->next;
		free(this);
		printf("Delete PW entry .\n");
		if(state==WITHDRAW_IN){
			printf("Delete vpn %d's incoming data plane forwarding information\n", vpn->vpn_id);
		}else if(state==WITHDRAW_OUT){
			printf("Delete vpn %d's outgoing data plane forwarding information\n", vpn->vpn_id);
		}else{
			printf("Delete data plane information.\n");
		}
		return 0;
	}else{
		prev=this;
		this=this->next;
		while(this!=NULL){
			if(this->remote_ip.s_addr==ip && (this->in_state==READY && state==WITHDRAW_IN) ||(this->out_state==READY && state==WITHDRAW_OUT)|| (state==WITHDRAW_DOIT) ){
				prev->next=this->next;
				free(this);
				printf("Delete PW entry .\n");
				if(state==WITHDRAW_IN){
					printf("Delete vpn %d's incoming data plane forwarding information\n", vpn->vpn_id);
				}else if(state==WITHDRAW_OUT){
					printf("Delete vpn %d's outgoing data plane forwarding information\n", vpn->vpn_id);
				}else{
					printf("Delete data plane information.\n");
				}
				return 0;
			}//end if
			prev=this;
			this=this->next;
		}//end while
	}
	return -1;
}

//like del_pw_info function  ; success : 1  fail : 0; no record this pw_entry : -1
int delete_pw(vpn_entry *vpn,unsigned long ip){
	printf("delete_pw function start\n");
	if(vpn->pw_info_ptr==NULL)
		return 0;
	pw_info_entry *this,*prev;
	this=vpn->pw_info_ptr;
	if(this->remote_ip.s_addr==ip){
		printf("free first PW entry\n");
		//free first PW entry
		vpn->pw_info_ptr=this->next;
		free(this);
		printf("Delete PW entry .\n");
		return 1;
	}else{
		printf("free next PW entry\n");
		prev=this;
		this=this->next;
		while(this!=NULL){
			if(this->remote_ip.s_addr==ip){
				prev->next=this->next;
				free(this);
				printf("Delete PW entry .\n");
				return 1;
			}//end if
			prev=this;
			this=this->next;
		}//end while
	}
	return -1;
}
//end vpn_entry process function block

//tunnel process function block<input type="checkbox" n<input type="checkbox" name="" value="">ame="" value="">
//success :1 ; fail :0;
int setup_tunnel(struct vty *vty,char *src_ip,char *dst_ip,int lsp_id){
	printf("Debug msg(setup_tunnel): src_ip :%s\t dst_ip:%s\t lsp_id :%d\n",src_ip,dst_ip,lsp_id);
	char buf[255];
	tunnel_entry *tunnel=tunnel_get();
	if(!tunnel){//no tunnel entry to add first new tunnel_entry
		tunnel=tunnel_new(); 	
		if(add_new_tunnel_entry(inet_addr(dst_ip),tunnel)){	
  	  vty_out(vty,"Create a new tunnel fail. %s",VTY_NEWLINE);
  	  return 0;
  	}else{//create new tunnel  	
 					connect_daemon(VTYSH_INDEX_RSVPD);	
 					RSVP_New_Command cmd;
 					cmd=SEND_PATH_MSG;
 					sprintf(buf,"rsvp_cmd_type %d arg0 %s arg1 %s arg2 %d arg3 %s\n",cmd,src_ip,dst_ip,lsp_id,"NULL");
 					vtysh_client_execute(&vtysh_client[VTYSH_INDEX_RSVPD], buf, stdout);
 					exit_daemon(VTYSH_INDEX_RSVPD);
 					return 1;
  	}
	}else{//have one or more tunnel_entry to check remote_ip address is used or unused;
		 //need to check remote_ip is used or unused
		  printf("Tunnel is exit then create new tunnel entry.\n");
   	 	if(qurray_tunnel_entry(inet_addr(dst_ip),tunnel)){
   	  	tunnel=tunnel_new_more(tunnel);
   	  	if(add_new_tunnel_entry(inet_addr(dst_ip),tunnel)){
   	  		vty_out(vty,"Create a new tunnel fail. %s",VTY_NEWLINE);
  	  		return 0;
   			}else{
	 			//need to check rsvp daemon is setup tunnel or not; those codes doesn't ready.
					RSVP_New_Command cmd;
 					cmd=SEND_PATH_MSG;
 					connect_daemon(VTYSH_INDEX_RSVPD);
 					sprintf(buf,"rsvp_cmd_type %d arg0 %s arg1 %s arg2 %d arg3 %s\n",cmd,src_ip,dst_ip,lsp_id,"NULL");
 					vtysh_client_execute(&vtysh_client[VTYSH_INDEX_RSVPD], buf, stdout);
 					exit_daemon(VTYSH_INDEX_RSVPD);
 					return 1;
	 			}
	 			//tunnel->out_state = PROCESSING;
				//return CMD_WARNING;
		 }else{
				vty_out(vty,"The remote_ip is already exit.\n");
				return 0;
			}
	}
}

//0 :sucess to enable tunnel state ; -1 : fail or used
int add_new_tunnel_entry (unsigned long dst_ip,tunnel_entry *tunnel)
{
	 tunnel->remote_ip.s_addr=dst_ip;
	 tunnel->in_use=USED;
	 return 0;
}

//0 :sucess remote ip already in tunnel entry -1: not found 
int qurray_tunnel_entry(unsigned long dst_ip,tunnel_entry * tunnel){
	char message[100];
	sprintf(message,"The remote_ip add_new_tunnel_entry : %s is already exit, please set other remote_ip address\n",inet_ntoa(tunnel->remote_ip));
	tunnel_entry *this;
	this=tunnel;
	while(this->next!=NULL){
		if(this->remote_ip.s_addr==dst_ip){
			printf("%s",message);
			//vty_out(vty,message);
			return 0;
		}
		this=this->next;	
	}
	if(this->remote_ip.s_addr==dst_ip){
		printf("%s",message);
		//vty_out(vty,message);
		return 0;	
	}else{
		return -1 ;
	}
	return -1;
}

//serarch vpn_entry by vpn_id  return vpn_entry address pointer
tunnel_entry *search_tunnel_node(tunnel_entry * tunnel,unsigned long dst_ip){
	tunnel_entry *this;
	this=tunnel;
	if(this->next!=NULL){
		do{
		if(this->remote_ip.s_addr==dst_ip)
			return this; 
		this=this->next;
		}while(this!=NULL);
	}else{
		if(this->remote_ip.s_addr==dst_ip)
			return this;
		else
			return NULL;
	}
	return NULL;
}


int withdraw_pw(vpn_entry *vpn,unsigned long ip,int state){
	vpn_entry *vpn_this;
	//pw_info_entry *pw_this;
	if(vpn!=NULL){
		vpn_this=vpn;
		while(vpn_this->next!=NULL){
			if(del_pw_info(vpn_this,ip,state)){
				printf("delete PW fail.\n");
				return -1;
			}else{
				//delete sucess
				printf("delete sucess.\n");
				return 0;
			}
			vpn_this=vpn_this->next;
		}//end while()
		//have only one vpn_entry not to check
	}else{
   printf("NO vpn_entry .\n");
   return -1;
	}
	return 0;
}

//0 :find the PW entry ; -1 : not find PW entry
int quarry_pw_info(vpn_entry *vpn,unsigned long ip,int vpn_id){
	if(vpn->pw_info_ptr==NULL)
		return -1;
	pw_info_entry *this,*prev;
	this=vpn->pw_info_ptr;
	if(this->remote_ip.s_addr==ip && this->in_state == READY && vpn->vpn_id ==vpn_id){
		printf("Find the PW entry in vpn_id :%d.\n",vpn->vpn_id);
		return 0;
	}else{
		this=this->next;
		while(this!=NULL){
			if(this->remote_ip.s_addr==ip && this->in_state == READY && vpn->vpn_id ==vpn_id){
				printf("Find the PW entry in vpn_id :%d.\n",vpn->vpn_id);
				return 0;
			}//end if 
			this=this->next;
		}//end while
	}
	return -1;
}
////end tunnel process


//need to rewrite search - quarry PW information function code
int search_vpn2pw_entry(vpn_entry *vpn,unsigned long ip){
	vpn_entry *vpn_this;
	if(vpn!=NULL){
		vpn_this=vpn;
		while(vpn_this->next!=NULL){
			if(search_pw_info(vpn_this,ip)){
				printf("quarry PW fail.\n");
				return -1;
			}else{
				//quarry sucess
				printf("Find PW entry in vpn_id : %d.\n",vpn_this->vpn_id);
				return 0;
			}
			vpn_this=vpn_this->next;
		}//end while()
		//have only one vpn_entry not to check
	}else{
   printf("NO vpn_entry .\n");
   return -1;
	}
	return 0;
}
int search_pw_info(vpn_entry *vpn,unsigned long ip){
	if(vpn->pw_info_ptr==NULL)
		return -1;
	pw_info_entry *this;//,*prev;
	this=vpn->pw_info_ptr;
	if(this->remote_ip.s_addr==ip ){
		printf("Find the PW entry in vpn_id :%d.\n",vpn->vpn_id);
		return 0;
	}else{
		this=this->next;
		while(this!=NULL){
			if(this->remote_ip.s_addr==ip ){
				printf("Find the PW entry in vpn_id :%d.\n",vpn->vpn_id);
				return 0;
			}//end if 
			this=this->next;
		}//end while
	}
	return -1;
}

pw_info_entry *get_pw_entry(vpn_entry *vpn,unsigned long ip){
	if(vpn->pw_info_ptr==NULL)
		return NULL;
	pw_info_entry *this;
	this=vpn->pw_info_ptr;
		if(this->remote_ip.s_addr==ip ){
			printf("Find the PW entry in vpn_id :%d.\n",vpn->vpn_id);
			return this;
		}else{
			this=this->next;
			while(this!=NULL){
				if(this->remote_ip.s_addr==ip ){
					printf("Find the PW entry in vpn_id :%d.\n",vpn->vpn_id);
					return this;
				}//end if 
				this=this->next;
			}//end while
		}//end (this->remote_ip.s_addr==ip )
	return NULL; 
}

//end need to rewrite search - quarry PW information function code
//link add_pw_by_ip
//set_state==0 -->set in_pw info ; set_state==2 --> set out_pw info
int setup_pw_info(vpn_entry *vpn,unsigned long ip,int set_state){
	//printf("setup_pw_info start .\n");
	pw_info_entry *pw,*new_node;
	
	pw=get_pw_entry(vpn,ip);
	if(!pw){
		new_node = (pw_info_entry *) malloc(sizeof(pw_info_entry));
		if (new_node == NULL){
			return -1;
		}
		new_node->next = NULL;
		new_node->remote_ip.s_addr = ip;
		if(set_state==0)
			new_node->in_state=PROCESSING;
		else 
			new_node->out_state=PROCESSING;
		//vpn->pw_info_ptr=new_node;
		if(vpn->pw_info_ptr == NULL){
			vpn->pw_info_ptr=new_node;
		}else{
			new_node->next=vpn->pw_info_ptr;
			vpn->pw_info_ptr=new_node;
		}
		return 0;
	}else{
		if(set_state==0)
			pw->in_state = PROCESSING;
		else
			pw->out_state = PROCESSING;
		return 0;
	}
	return 0;
	
}
