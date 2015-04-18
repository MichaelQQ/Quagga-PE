#include "zebra.h"
#include "command.h"
#include "log.h"

#include "vpnm.h"
#include "vpnmd_main.h"
#include "vpnmd_rsvp_msg.h"
#include "vpnmd_ldp_msg.h"
#include "vpnm_via_ldp.h"
#include "vpnm_via_rsvp.h"
#include "vpnm_via_brctl.h"
#include "connect_daemon.h"

DEFUN(router_vpnmd,
	router_vpnmd_cmd,
	"router vpnmd",
	"Enable a routing process "
	" VPNMD process")
{
 vty->node = VPNMD_NODE;
 vty_out (vty, "Down to vpnmd node%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  tunnel_status_vpnmd,
        tunnel_status_vpnmd_cmd,
        "tunnel_status",
        "show tunnel status "
        "VPNMD process")
{
 vty->node = VPNMD_NODE;
 tunnel_entry *tunnel=tunnel_get(); 
 show_tunnel_info(vty,tunnel);
 return CMD_SUCCESS;
}

DEFUN(  show_vpls_info_vpnmd,
        show_vpls_info_vpnmd_cmd,
        "show_vpls_info",
        "show vpls info "
        "VPNMD process")
{
	vpn_entry *vpn = vpn_get();
	tunnel_entry *tunnel=tunnel_get();
	show_vpls_info(vty,vpn,tunnel);
	return CMD_SUCCESS;
}

DEFUN(  show_vpls_pw_vpnmd,
        show_vpls_pw_vpnmd_cmd,
        "show_vpls_pw_info",
        "show vpls PW information "
        "VPNMD process")
{ 
  vpn_entry *vpn = vpn_get();
  if(!vpn){
		vty_out (vty, "There isn't an active LDP instance.%s", VTY_NEWLINE);
		return CMD_WARNING;
  }
  show_pw_info(vty,vpn);
  return CMD_SUCCESS;
}
//end test

DEFUN(  add_vpls_id_vpnmd,
        add_vpls_id_vpnmd_cmd,
        "add_vpls_id vpn_id <0-65534>",
        "add vpls id"
        "VPNMD process")
{
 char	br_name[50]={0};
 vty->index=vpn_get();
 if(!vty->index){ //no vpn entry to add first new vpn_entry
 	vty->index = vpn_new();
	if (!vty->index) {
	    vty_out (vty, "Unable to create VPN instance.%s", VTY_NEWLINE);
	    return CMD_WARNING;
	}else{
	    vpn_entry *vpn = vpn_get();
	    vpn->in_use=USED;
	    vpn->vpn_id=atoi(argv[0]);//set vpn_id;
 	    vty_out(vty,"add_vpls_id vpn_id %d %s",atoi(argv[0]),VTY_NEWLINE);
 	    //create the new virtual bridge device ;
 	    //Ex:vpn_id =100 the vpls bridge name="br100";
 	   	sprintf(br_name,"br%d",atoi(argv[0]));
 	    add_bridge(br_name);
	}
 }else{//have one or more vpn_entry to check vpn_id is used or unused;
   	if(qurray_vpn_entry(vty,vty->index,atoi(argv[0]))){
   	//create new vpn_entry 
   	 vty->index=vpn_new_more(vty->index);
   	 	if(!vty->index){
   	 	vty_out (vty, "Unable to create VPN instance.%s", VTY_NEWLINE);
	    	return CMD_WARNING;
   	 	}else{
	     vpn_entry *vpn = vpn_get();
	     vpn->in_use=USED;
	   	 vpn->vpn_id=atoi(argv[0]);//set vpn_id;
 	  	 vty_out(vty,"add_vpls_id vpn_id %d %s",atoi(argv[0]),VTY_NEWLINE);
 	  	 //create the new virtual bridge device ;
 	     //Ex:vpn_id =100 the vpls bridge name="br100";
 	     sprintf(br_name,"br%d",atoi(argv[0]));
 	     add_bridge(br_name);
   	 	}
   	}else{ 
   	//vpn id is already exit 
   	 	vty_out(vty,"VPN_id %d is already exit.%s",argv[0],VTY_NEWLINE);
   	 	return CMD_WARNING;
   	}
 }
 return CMD_SUCCESS;
}
//rewrite set_vpls_port cmd 
DEFUN(  vpnmd_set_cstomer_facing_port,
        vpnmd_set_cstomer_facing_port_cmd,
        "set_customer_facing_port vpn_id <0-65534> iface WORD",
        "set_customer_facing_port vpn_id-int iface-string "
        "VPNMD process")
{
	char br_name[15]={0};
	
	int ret=-1;
	ret=set_customer_facig_port(atoi(argv[0]),argv[1]);
	if(ret==-1)
		vty_out(vty, "There isn't an active VPN instance.%s", VTY_NEWLINE);
	else{	
		vty_out(vty, "OK.%s", VTY_NEWLINE);
		sprintf(br_name,"br%d",atoi(argv[0]));
		set_vpls_bridge(br_name);
	}
	return CMD_SUCCESS;
}
//rewrite del_vpls_port cmd 
DEFUN(  vpnmd_del_cstomer_facing_port,
        vpnmd_del_cstomer_facing_port_cmd,
        "del_customer_facing_port vpn_id <0-65534> iface WORD",
        "set_customer_facing_port vpn_id-int iface-string "
        "VPNMD process")
{
	char br_name[15]={0};
	int ret=-1;
	ret=delete_customer_facig_port(atoi(argv[0]),argv[1]);
	if(ret==-1)
		vty_out(vty, "There isn't an active VPN instance.%s", VTY_NEWLINE);
	else{	
		vty_out(vty, "OK.%s", VTY_NEWLINE);
		clear_vpls_bridge(br_name);
	}
	return CMD_SUCCESS;
}

//old command to set customer-facing port informations. 
//new cmd set_customer_facig_port
DEFUN(  set_vpls_port_vpnmd,
        set_vpls_port_vpnmd_cmd,
        "set_vpls_port vpn_id <0-65534> port_id <0-65534>",
        "set vpls port infomation"
        "VPNMD process")
{
 vty->node = VPNMD_NODE; 
 vpn_entry *vpn = vpn_get();
 if (!vpn){
	vty_out (vty, "There isn't an active VPN instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
 }
 vpn=search_vpn_node(vpn,atoi(argv[0]));
 if(!vpn){
 	vty_out(vty,"please firest set vpn_id :%d\n",atoi(argv[0]));
 	return CMD_WARNING;
 }
 //need to use vpn_id get vpn entry ; this code is not ready;
 int retval=0;
 retval=add_port_info(vty,vpn,atoi(argv[1]));
 if(retval==1){
 char buf[50];
 sprintf(buf,"set_vpls_port vpn_id %d port_id %d",atoi(argv[0]),atoi(argv[1]));
 vty_out(vty,buf);
 }else{
  vty_out(vty,"NOT SUCCESS SET VPLS PORT INFOMATION.\n ");
  return CMD_WARNING;
 }
 return CMD_SUCCESS;
}
//old command to set customer-facing port informations. 
//new cmd del_customer_facig_port
DEFUN(  del_vpls_port_vpnmd,
        del_vpls_port_vpnmd_cmd,
        "del_vpls_port vpn_id <0-65534> port_id <0-65534>",
        "del vpls port infomation"
        "VPNMD process")
{
 vty->node = VPNMD_NODE; 
 vpn_entry *vpn = vpn_get();
 vpn=search_vpn_node(vpn,atoi(argv[0]));
    if (!vpn) {
	vty_out (vty, "There isn't an active VPN instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
    }
 //need to use vpn_id get vpn entry ; this code is not ready;
 int retval=0;
 retval=del_port(vpn,atoi(argv[1]));
 if(retval==0){
 	char buf[50];
 	sprintf(buf,"del_vpls_port vpn_id %d port_id %d",atoi(argv[0]),atoi(argv[1]));
 	vty_out(vty,buf);
 }else{
 	vty_out(vty,"NOT SUCCESS CLEAR VPLS PORT INFOMATION.\n ");
  	return CMD_WARNING;
 }
 return CMD_SUCCESS;
}
DEFUN(  del_vpls_info_vpnmd,
        del_vpls_info_vpnmd_cmd,
        "del_vpls_info vpn_id <0-65534>",
        "del vpls infomation"
        "VPNMD process")
{
 vty->node = VPNMD_NODE;
 vpn_entry *vpn = vpn_get();
 if (!vpn){
	vty_out (vty, "There isn't an active VPN instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
 }
 char buf[50];
 sprintf(buf,"del_vpls_info vpn_id %d",atoi(argv[0]));
 if(!del_vpn_info(vpn,atoi(argv[0])))
 	vty_out(vty,buf);
 else
 	vty_out(vty,"delete vpls info fail.\n");
 	
 return CMD_SUCCESS;
}
DEFUN(  send_hello_vpnmd,
        send_hello_vpnmd_cmd,
        "send_hello remote_ip WORD",
        "send ldp hello message "
        "VPNMD process")
{
 vty->node = VPNMD_NODE;
 char buf[255];
 LDP_Command cmd;
 cmd=ldpSendHello;
 connect_daemon(VTYSH_INDEX_LDP);
 sprintf(buf,"cmd_type %d arg0 %s arg1 %s arg2 %s arg3 %s\n",cmd,argv[0],"NULL","NULL","NULL");
 printf("send_buf : %s\n",buf);
 vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LDP], buf, stdout);
 exit_daemon(VTYSH_INDEX_LDP);
 //need to check ldp daemon is send hello message or not; those codes doesn't ready.
 return CMD_SUCCESS;
}

DEFUN(  stop_hello_vpnmd,
        stop_hello_vpnmd_cmd,
        "stop_hello remote_ip WORD",
        "stop to send ldp hello message "
        "VPNMD process")
{
 vty->node = VPNMD_NODE; 
 char buf[255];
 LDP_Command cmd;
 cmd=ldpStopHello;
 connect_daemon(VTYSH_INDEX_LDP);
 sprintf(buf,"cmd_type %d arg0 %s arg1 %s arg2 %s arg3 %s\n",cmd,argv[0],"NULL","NULL","NULL");
 vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LDP], buf, stdout);
 exit_daemon(VTYSH_INDEX_LDP);
 //need to check ldp daemon is send hello message or not; those codes doesn't ready.
 return CMD_SUCCESS;
}

DEFUN(  setup_tunnel_vpnmd,
        setup_tunnel_vpnmd_cmd,
        "setup_tunnel dst_ip WORD lsp_id <0-65534>",
        "setup vpls tunnel "
        "VPNMD process")
{
	nic_info *nic;
	nic=nic_get();
	if(setup_tunnel(vty,nic->ip,argv[0],atoi(argv[1]))>0)
		return CMD_SUCCESS;
	else
		return CMD_WARNING;
}

DEFUN(  setup_pw_vpnmd,
        setup_pw_vpnmd_cmd,
        "setup_pw remote_pe_ip WORD vpn_id <0-65534>",
        "setup vpls pw "
        "VPNMD process")
{
 //vty->node = VPNMD_NODE; 
 vpn_entry *vpn = vpn_get();
 
 if (!vpn){//not find vpn entry
	vty_out (vty, "There isn't an active VPN instance.%s", VTY_NEWLINE);
	return CMD_WARNING;
 }else{//find vpn entry 
 	vpn=search_vpn_node(vpn,atoi(argv[1]));
 	if(!vpn){
 		vty_out(vty,"The vpn_id : %d doesn't set.%s",atoi(argv[1]),VTY_NEWLINE);
		return CMD_WARNING;
	}
 	if(quarry_pw_info(vpn,inet_addr(argv[0]),atoi(argv[1]))){//Not setup PW entry before.
		vty_out(vty,"Setup a new PW.%s",VTY_NEWLINE);
		char buf[255];
		int pw_in_lable;
		LDP_Command cmd;
 		cmd=ldpVCInfo;
 		connect_daemon(VTYSH_INDEX_LDP);
 		sprintf(buf,"cmd_type %d arg0 %d arg1 %d arg2 %d arg3 %s\n",cmd,0x05,atoi(argv[1]),0,argv[0]);
 		pw_in_lable=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LDP], buf, stdout);
 		exit_daemon(VTYSH_INDEX_LDP);
 		printf("vpnmd get pw_lable : %d from ldpd.\n",pw_in_lable);
 		setup_pw_info_here(vty,atoi(argv[1]),inet_addr(argv[0]),pw_in_lable);
	}else{//To talk LDP daemon to setup PW entry. if tunnel not setup also need to setup tunnel .
		// setup pw and setup tunnel no  order to setup.
		vty_out(vty,"qurray_vpn2pw_entry SUCCESS.(The PW have setup before .)%s",VTY_NEWLINE);
	}
 }
 return CMD_SUCCESS;
}

DEFUN(  withdraw_tunnel_vpnmd,
        withdraw_tunnel_vpnmd_cmd,
        "withdraw_tunnel dst_ip WORD lsp_id <0-65534>",
        "withdraw out tunnel lsp "
        "VPNMD process")
{
	nic_info *nic;
	nic=nic_get();
	tunnel_entry *tunnel=tunnel_get();
	tunnel_entry *tunnel_this;
	char buf[255];
	if(!tunnel){
		vty_out(vty,"No tunnel information.%s",VTY_NEWLINE);
		return CMD_WARNING;	
	}else{
		tunnel_this=search_tunnel_node(tunnel,inet_addr(argv[0]));
		//need to confirm lsp id and to withdraw the lsp
		if(tunnel_this->out_state != NOT_READY){
			//talk to rsvp-te to withdraw this lsp
			RSVP_New_Command cmd;
 			cmd=WITHDRAW_TUNNEL;
 			connect_daemon(VTYSH_INDEX_RSVPD);
 			sprintf(buf,"rsvp_cmd_type %d arg0 %s arg1 %s arg2 %d arg3 %s\n",cmd,nic->ip,argv[0],atoi(argv[1]),"NULL");
 			vtysh_client_execute(&vtysh_client[VTYSH_INDEX_RSVPD], buf, stdout);
 			exit_daemon(VTYSH_INDEX_RSVPD);
			return CMD_SUCCESS;
		}else{
			//this lsp isn't ready 
			printf("The lsp_id %d isn't ready ",atoi(argv[1]));
			return CMD_WARNING;
		}
	}
}

DEFUN(  release_tunnel_vpnmd,
        release_tunnel_vpnmd_cmd,
        "release_tunnel dst_ip WORD lsp_id <0-65534>",
        "release in tunnel lsp "
        "VPNMD process")
{
	nic_info *nic;
	nic=nic_get();
	tunnel_entry *tunnel=tunnel_get();
	tunnel_entry *tunnel_this;
	char buf[255];
	if(!tunnel){
		vty_out(vty,"No tunnel information.%s",VTY_NEWLINE);
		return CMD_WARNING;	
	}else{
		tunnel_this=search_tunnel_node(tunnel,inet_addr(argv[0]));
		//need to confirm lsp id and to withdraw the lsp
		if(tunnel_this->in_state != NOT_READY){
			//talk to rsvp-te to withdraw this lsp
			RSVP_New_Command cmd;
 			cmd=RELEASE_TUNNEL;
 			connect_daemon(VTYSH_INDEX_RSVPD);
 			sprintf(buf,"rsvp_cmd_type %d arg0 %s arg1 %s arg2 %d arg3 %s\n",cmd,nic->ip,argv[0],atoi(argv[1]),"NULL");
 			vtysh_client_execute(&vtysh_client[VTYSH_INDEX_RSVPD], buf, stdout);
 			exit_daemon(VTYSH_INDEX_RSVPD);
			return CMD_SUCCESS;
		}else{
			//this lsp isn't ready 
			printf("The lsp_id %d isn't ready ",atoi(argv[1]));
			return CMD_WARNING;
		}
	}
}

DEFUN(  withdraw_pw_vpnmd,
        withdraw_pw_vpnmd_cmd,
        "withdraw_pw remote_ip WORD vpn_id <0-65534>",
        "withdraw vpls pw "
        "VPNMD process")
{
	vpn_entry *vpn = vpn_get();
 	pw_info_entry *pw;
 	int retval=0;//To check LDPd executed commands is SUCCESS or fail; 
 	char buf[255];
	if(!vpn){//not find vpn entry
		vty_out (vty, "There isn't an active VPN instance.%s", VTY_NEWLINE);
		return CMD_WARNING;
 	}else{//find vpn entry
		vpn=search_vpn_node(vpn,atoi(argv[1]));
 		if(!vpn){
 			vty_out(vty,"The vpn_id : %d doesn't set.%s",atoi(argv[1]),VTY_NEWLINE);
			return CMD_WARNING;
		}
		//To check PW entry and withdraw those informations.
		pw=get_pw_entry(vpn,inet_addr(argv[0]));
		if(!pw){
 			vty_out(vty,"The VPN_ID :%d no PW entry.%s",atoi(argv[1]),VTY_NEWLINE);
			return CMD_WARNING;
		}
		if(pw->in_state!= NOT_READY){// READY or PROCESS state need to withdraw pw
			LDP_Command cmd;
		 	cmd=ldpWithdrawPW;
 			connect_daemon(VTYSH_INDEX_LDP);
 			sprintf(buf,"cmd_type %d arg0 %d arg1 %d arg2 %d arg3 %s\n",cmd,0x05,atoi(argv[1]),pw->in_pw_label,argv[0]);
 			retval=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LDP], buf, stdout);
			if(retval){
				//withdraw_pw_info(atoi(argv[1]),inet_addr(argv[0]));
				printf("SUCCESS to withdraw the in_pw information .\n");
				
				pw->in_state=NOT_READY;
				pw->in_pw_label=0;
			}else{
				printf("fail to withdraw the in_pw information.\n");
			}
			exit_daemon(VTYSH_INDEX_LDP);
		}
		if(pw->out_state!= NOT_READY){// READY or PROCESS state need to release pw
 			LDP_Command cmd;
		 	cmd=ldpReleasePW;
 			connect_daemon(VTYSH_INDEX_LDP);
 			sprintf(buf,"cmd_type %d arg0 %d arg1 %d arg2 %d arg3 %s\n",cmd,0x05,atoi(argv[1]),pw->out_pw_label,argv[0]);
 			retval=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LDP], buf, stdout);
			if(retval){
				//release_pw_info(atoi(argv[1]),inet_addr(argv[0]));
				printf("SUCCESS to release the out_pw information .\n");
				pw->out_state=NOT_READY;
				pw->out_pw_label=0;
			}else{
				printf("fail to release the in_pw information.\n");
			}
			exit_daemon(VTYSH_INDEX_LDP);
		}
		if(pw->in_state==NOT_READY && pw->out_state==NOT_READY){
			//DELETE pw entry and kill ldp session
			if(!delete_pw(vpn,inet_addr(argv[0]))){
				printf("delete_pw function SUCCESS.\n");
				LDP_Command cmd;
 				cmd=ldpStopHello;
 				connect_daemon(VTYSH_INDEX_LDP);
 				sprintf(buf,"cmd_type %d arg0 %s arg1 %s arg2 %s arg3 %s\n",cmd,argv[0],"NULL","NULL","NULL");
 				vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LDP], buf, stdout);
 				exit_daemon(VTYSH_INDEX_LDP);
			}
		}
	} 
	return CMD_SUCCESS;
}
/*This command to set network interface information . 
Only need to set core network NIC .
Next step this information will get from zebra. 
LSP_ID will be get by rsvp
*/
DEFUN(set_interface_vpnmd,
      set_interface_vpnmd_cmd,
      "interface WORD ip_addr WORD lsp_id <1-60>",
      "Only used for ldpd send command message to vpnmd "
      "vpn manager process")
{
	nic_info *nic;
	nic=nic_new();
	strcpy(nic->if_name,argv[0]);
	strcpy(nic->ip,argv[1]);
	nic->lsp_id=atoi(argv[2]);
	return CMD_SUCCESS;
}
//add by here . This command is used for ldpd ->vpnmd
DEFUN(ldp_talk_to_vpnmd,
      ldp_talk_to_vpnmd_cmd,
      "ldpCmd_type <0-4> arg0 WORD arg1 WORD arg2 WORD arg3 WORD",
      "Only used for ldpd send command message to vpnmd "
      "vpn manager process")
{
	printf("ldp_talk_to_vpnmd start. argv[0]:%d argv[1]:%d  argv[2]:%d argv[3]:%s argv[4]:%s argv[5]:%s\n",atoi(argv[0]),atoi(argv[1]),atoi(argv[2]),argv[3],argv[4],argv[5]);
 	switch(atoi(argv[0])){
 		case vpnmInPWLabel:
 			printf("cmd_type : %s\n","vpnmInPWLabel");
 			set_in_pw_info(vty,atoi(argv[1]),inet_addr(argv[2]),atoi(argv[3]));
 			break;
 		case vpnmSessionState:
 			printf("cmd_type : %s\n","vpnmSessionState");
 			//printf("state :%d vpn_id: %d remote_ip :%s\n",atoi(argv[1]),atoi(argv[2]),argv[3]);
 			//setup_pw_info_here(atoi(argv[2]),atoi(argv[3]),inet_addr(argv[4]));
 			break;
 		case vpnmRcvLdpWithdrawMsg:
 			printf("cmd_type : %s\n","vpnmRcvLdpWithdrawMsg");
 			withdraw_pw_info(atoi(argv[1]),inet_addr(argv[2]));
 			break;
 		case vpnmRcvLdpReleaseMsg:
 			printf("cmd_type : %s\n","vpnmRcvLdpReleaseMsg");
 		  release_pw_info(atoi(argv[1]),inet_addr(argv[2]));
 			break;
 		case vpnmOutPwLabel:
 			printf("cmd_type : %s\n","vpnmOutPwLabel");
 			set_out_pw_info(atoi(argv[1]),inet_addr(argv[2]),atoi(argv[3]));
 			break;
 		default :
 			printf("cmd_type : %s\n","Not support this command");
 			break;
 	}
 return CMD_SUCCESS;
}
//add by here . This command is used for rsvp->vpnmd
DEFUN(rsvp_talk_to_vpnmd,
      rsvp_talk_to_vpnmd_cmd,
      "rsvpCmd_type <0-4> arg0 WORD arg1 WORD arg2 WORD arg3 WORD arg4 WORD arg5 WORD",
      "Only used for rsvpd send command message to vpnmd "
      " ldpd protocol")
{ 
	printf("arg0 :%s arg1 :%s argv2 :%s argv3 :%s argv4 :%s argv5:%s\n",argv[1],argv[2],argv[3],argv[4],argv[5],argv[6]);
 	
 	switch(atoi(argv[0])){
 		case vpnmInTunnelLable:
 			printf("cmd_type : %s\n","vpnmInTunnelLable");
 			add_in_tunnel_label(atoi(argv[1]),argv[2],inet_addr(argv[3]),atoi(argv[6]));
 			//set_in_pw_info(atoi(argv[1]),inet_addr(argv[2]),atoi(argv[3]));
 			break;
 		case vpnmOutTunnelLable: //not ready for use ; the next_hop_ip is not ready
 			printf("cmd_type : %s\n","vpnmOutTunnelLable");
 			//olabel,out_if,dst_ip,next_hop_ip,nhlfe_key,lsp_id
 			add_out_tunnel_label(atoi(argv[1]),argv[2],inet_addr(argv[3])
 			,inet_addr(argv[4]),atoi(argv[5]),atoi(argv[6]));
 			break;
 		case vpnmRcvPathtearMsg:
 			printf("cmd_type : %s\n","vpnmRcvPathtearMsg");
 			pro_pathtear_msg(inet_addr(argv[1]));
 			//withdraw_pw_info(atoi(argv[1]),inet_addr(argv[2]));
 			break;
 		case vpnmRcvResvtearMsg:
 			printf("cmd_type : %s\n","vpnmRcvResvtearMsg");
 			pro_resvtear_msg(inet_addr(argv[1]));
 		  //release_pw_info(atoi(argv[1]),inet_addr(argv[3]));
 			break;
 		case vpnmReleaseTunnel:
 			printf("cmd_type : %s\n","vpnmReleaseTunnel");
 			release_tunnel(atoi(argv[1]),inet_addr(argv[4]));
 			break;
 		default :
 			printf("cmd_type : %s\n","Not support this command");
 			break;
 	}
 return CMD_SUCCESS;
}
//end by here
//end by here  for vpn manager

static struct cmd_node vpnmd_node =
{ VPNMD_NODE, "%s(config-vpnmd)# ", 1 };

void vpnmd_init(void)
{
  install_node( &vpnmd_node, NULL );
  install_default( VPNMD_NODE );
  // Only for ldpd & rsvpd use for commnuicate with vpnmd
	install_element( VIEW_NODE,  &ldp_talk_to_vpnmd_cmd);
  install_element( VIEW_NODE,  &rsvp_talk_to_vpnmd_cmd);
  //end only for ldp & rsvpd
  install_element( CONFIG_NODE, &router_vpnmd_cmd); 
  install_element( CONFIG_NODE, &set_interface_vpnmd_cmd);
  //Testing code cmd
  install_element( VPNMD_NODE, &show_vpls_info_vpnmd_cmd);
  install_element( VPNMD_NODE, &show_vpls_pw_vpnmd_cmd);
  install_element( VPNMD_NODE, &vpnmd_set_cstomer_facing_port_cmd);
  install_element( VPNMD_NODE, &vpnmd_del_cstomer_facing_port_cmd);
  //end testing code cmd  
  install_element( VPNMD_NODE,  &tunnel_status_vpnmd_cmd);
  install_element( VPNMD_NODE,  &add_vpls_id_vpnmd_cmd);
  install_element( VPNMD_NODE,  &set_vpls_port_vpnmd_cmd);
  install_element( VPNMD_NODE,  &del_vpls_port_vpnmd_cmd);
  install_element( VPNMD_NODE,  &del_vpls_info_vpnmd_cmd);
  install_element( VPNMD_NODE,  &send_hello_vpnmd_cmd); 
  install_element( VPNMD_NODE,  &stop_hello_vpnmd_cmd);
  install_element( VPNMD_NODE,  &setup_tunnel_vpnmd_cmd); 
  install_element( VPNMD_NODE,  &setup_pw_vpnmd_cmd);
  install_element( VPNMD_NODE,  &withdraw_tunnel_vpnmd_cmd); 
  install_element( VPNMD_NODE,  &release_tunnel_vpnmd_cmd); 
  install_element( VPNMD_NODE,  &withdraw_pw_vpnmd_cmd); 
}
