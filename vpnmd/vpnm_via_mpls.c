#include <stdio.h>
#include "vpnm_via_mpls.h"
#include "connect_daemon.h"
#include "vpnmd_table.h"

static int add_label_to_packet(int il,int labelspace);
static int add_otunnel_packet(const char* iface);
static int bind_olabel(int label, int key,int labelspace);
static int create_tunnel_interface(char* mplsiface);
static int map_label_tunnel(int labelref,const char* mplsiface);
static int del_tunnel(char* mplsiface);
static int del_label_to_label(int il, int okey);
static int connect_mplsd();
static int disconnect_mplsd();

char buf[1024]={0};

static int connect_mplsd(){
	connect_daemon(VTYSH_INDEX_MPLSADMD);
	return 0;
}
static int disconnect_mplsd(){
	exit_daemon(VTYSH_INDEX_MPLSADMD);
	return 0;
}
static int add_label_to_packet(int il,int labelspace){
	//add_label_to_packet il <0-65535> labelspace <1-65535>
	int retval=-1;
	sprintf(buf,"add_label_to_packet il %d labelspace %d",il,labelspace);
	retval=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	return retval;
}
static int add_otunnel_packet(const char* iface){
	//add_otunnel_packet iface WORD
	sprintf(buf,"add_otunnel_packet iface %s",iface);
	vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	return 0;
}

static int add_label_stack(int nhlfe_key,int olabel){
	//add_label_stack label_key <1-65535> label <1-65535>
	int retval=-1;
	sprintf(buf,"add_label_stack label_key %d label %d",nhlfe_key,olabel);
	retval=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	return retval;
}
static int bind_olabel(int label, int key,int labelspace){
	//bind_olabel ilabel <1-65535> olabelkey <1-65535> labelspace <0-65535>
	sprintf(buf,"bind_olabel ilabel %d olabelkey %d labelspace %d",label,key,labelspace);
	vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	return 0;
}
static int create_tunnel_interface(char* mplsiface){
	//create_tunnel_interface mplsiface WORD
	//create_tunnel_interface mplsiface WORD
	sprintf(buf,"create_tunnel_interface mplsiface %s",mplsiface);
	vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	return 0;
}
static int map_label_tunnel(int labelref,const char* mplsiface){
	//map_label_tunnel labelref <1-65535> mplsiface WORD
	sprintf(buf,"map_label_tunnel labelref %d mplsiface %s",labelref,mplsiface);
	vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	return 0;
}
static int del_tunnel(char* mplsiface){
	//del_tunnel mplsiface WORD
	sprintf(buf,"del_tunnel mplsiface %s",mplsiface);
	vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	return 0;
}
static int del_label_to_label(int il, int okey){
	//del_label_to_label ilabel <1-65535> okey <1-65535>
	sprintf(buf,"del_label_to_label ilabel %d okey %d",il,okey);
	vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	return 0;
}

//To use set out && in VC LSP nhlfe/ILM entry
int set_pw_data_plane(const char *pw_if,int olabel,int nhlfe_key,int ilabel){
//pw_if,olabel,key,ilabel, 
/*
./mpls tunnel add dev mpls100
./mpls nhlfe add key 0 instructions push gen 100 forward 0x2
(return 0x03)
./mpls tunnel set dev mpls100 nhlfe 0x03

 Updating ILM table
./mpls labelspace set dev eth2 labelspace 0
./mpls ilm add label gen 601 labelspace 0 proto packet
./mpls ilm add label gen 101 labelspace 0 proto packet
./mpls nhlfe add key 0 instructions nexthop mpls100 packet
(returns key 0x4)
./mpls xc add ilm_label gen 101 ilm_labelspace 0 nhlfe_key 0x4
*/
	int okey=-1;
	//writing outgoing VC_LSP information into NHLFE entry
	connect_mplsd();
	//use the "pw_in_label" to create tunnnel interface.
	create_tunnel_interface(pw_if);
	okey=add_label_stack(nhlfe_key,olabel);

	if(okey <= 0){
		disconnect_mplsd();
		return -1;
	}else{
		map_label_tunnel(okey,pw_if);
	}
	//writing incoming VC_LSP information into ILM entry
	add_label_to_packet(ilabel,0); //default labelspace =0
	okey=add_otunnel_packet(pw_if);
	if(okey <= 0){
		disconnect_mplsd();
		return -1;
	}else{
		bind_olabel(ilabel,okey,0);//default labelspace =0
	}
	disconnect_mplsd();
	return 0;
}
int del_pw_data_plane(){
	return 0;
}

int set_out_vclsp(const char *pw_if,int olabel,int nhlfe_key,int pw_in_state){
//writing outgoing VC_LSP information into NHLFE entry
/*
./mpls tunnel add dev mpls100
./mpls nhlfe add key 0 instructions push gen 100 forward 0x2
(return 0x03)
./mpls tunnel set dev mpls100 nhlfe 0x03
*/
/*
	int okey=-1;
	//writing outgoing VC_LSP information into NHLFE entry
	connect_mplsd();
	if(pw_in_state!=READY)
		create_tunnel_interface(pw_if);
	okey=add_label_stack(nhlfe_key,olabel);
	
	if(okey <= 0){
		disconnect_mplsd();
		return -1;
	}else{
		map_label_tunnel(okey,pw_if);
		return 0;
	}
	*/
	printf("DEBUG(VPN Manager)set_out_vclsp enter.\n ");
	int okey=-1;
	connect_daemon(VTYSH_INDEX_MPLSADMD);
	if(pw_in_state!=READY){
		sprintf(buf,"create_tunnel_interface mplsiface %s",pw_if);
 		okey=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	}
	sprintf(buf,"add_label_stack label_key %d label %d",nhlfe_key,olabel);
	okey=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	if(okey <= 0){
		vclient_close(&vtysh_client[VTYSH_INDEX_MPLSADMD]);
		return -1;
	}else{
		//map_label_tunnel(okey,pw_if);
		sprintf(buf,"map_label_tunnel labelref %d mplsiface %s",okey,pw_if);
		vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	}
	vclient_close(&vtysh_client[VTYSH_INDEX_MPLSADMD]);
	printf("DEBUG(VPN Manager)set_out_vclsp exit.\n ");
	return 0;
}

int set_in_vclsp(const char *pw_if,int ilabel,int pw_out_state){
/*
Updating ILM table
./mpls labelspace set dev eth2 labelspace 0
./mpls ilm add label gen 601 labelspace 0 proto packet
./mpls ilm add label gen 101 labelspace 0 proto packet
./mpls nhlfe add key 0 instructions nexthop mpls100 packet
(returns key 0x4)
./mpls xc add ilm_label gen 101 ilm_labelspace 0 nhlfe_key 0x4
*/
	printf("DEBUG(VPN Manager)set_in_vclsp enter.\n ");
	/*
	int okey=-1;
	//writing incoming VC_LSP information into ILM entry
	//use the "pw_in_label" to create tunnnel interface.
	connect_mplsd();
	if(pw_out_state!=READY)
		create_tunnel_interface(pw_if);
		
	add_label_to_packet(ilabel,0); //default labelspace =0
	okey=add_otunnel_packet(pw_if);
	if(okey <= 0){
		disconnect_mplsd();
		return -1;
	}else{
		bind_olabel(ilabel,okey,0);//default labelspace =0
	}
	disconnect_mplsd();
	return 0;
	*/
	int okey;
	connect_daemon(VTYSH_INDEX_MPLSADMD);
	if(pw_out_state!=READY){
  	sprintf(buf,"create_tunnel_interface mplsiface %s",pw_if);
 		okey=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	}
	//add_label_to_packet il <0-65535> labelspace <1-65535>
	printf("il:%d\n",ilabel);
	sprintf(buf,"add_label_to_packet il %d labelspace %d",ilabel,0);//default labelspace =0
	okey=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	sprintf(buf,"add_otunnel_packet iface %s",pw_if);
	okey=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	if(okey <= 0){
		vclient_close(&vtysh_client[VTYSH_INDEX_MPLSADMD]);
		return -1;
	}else{
		sprintf(buf,"bind_olabel ilabel %d olabelkey %d labelspace %d",ilabel,okey,0);//default labelspace =0
		vtysh_client_execute(&vtysh_client[VTYSH_INDEX_MPLSADMD], buf, stdout);
	}
	vclient_close(&vtysh_client[VTYSH_INDEX_MPLSADMD]);
	printf("DEBUG(VPN Manager)set_in_vclsp exit.\n ");
	return 0;
}