#include "zebra.h"
#include "command.h"
#include "log.h"
#include "libmpls.h"
//#include "mpls.h"
int retval=0;

DEFUN(	show_mpls_nhlfe	,
	show_mpls_nhlfe_cmd	,
	"show mpls nhlfe "	,
	"show mpls nhlfe table informations"	) {
		
	flush_mpls_buffer();
	char buf[1024]={0};	
	int retval=-1;
  retval=show_mplsd_nhlfe();
  sprintf(buf,"%s",get_mpls_table());
  vty_out(vty,"%s%s",buf,VTY_NEWLINE);	
	
	return CMD_SUCCESS;
}
	
DEFUN(	show_mpls_ilm	,
	show_mpls_ilm_cmd	,
	"show mpls ilm "	,
	"show mpls ilm table informations"	) {
		
	flush_mpls_buffer();
	char buf[1024]={0};	
	int retval=-1;
  retval=show_mplsd_ilm();
  sprintf(buf,"%s",get_mpls_table());
  vty_out(vty,"%s%s",buf,VTY_NEWLINE);	
	
	return CMD_SUCCESS;
}

DEFUN(	show_mpls_labelspace	,
	show_mpls_labelspace_cmd	,
	"show mpls labelspace "	,
	"show mpls NIC labelspace informations"	) {
	flush_mpls_buffer();
	char buf[1024]={0};	
	int retval=-1;
  retval=show_mplsd_labelspace();
  sprintf(buf,"%s",get_mpls_table());
  vty_out(vty,"%s%s",buf,VTY_NEWLINE);	
	return CMD_SUCCESS;
}

DEFUN(	show_mpls_xc	,
	show_mpls_xc_cmd	,
	"show mpls xc "	,
	"show mpls cross-connect table informations"	) {
	flush_mpls_buffer();
  char buf[1024]={0};	
	int retval=-1;
	retval=show_mplsd_xc();
	sprintf(buf,"%s",get_mpls_table());
  vty_out(vty,"%s%s",buf,VTY_NEWLINE);	
	return CMD_SUCCESS;
}
//New commands to support VPLS technology capability
DEFUN(mplsd_add_label_to_packet	,
	mplsd_add_label_to_packet_cmd	,
	"add_label_to_packet il <0-65535> labelspace <0-65535>"	,
	"add_label_to_packet il-int labelspace-int "	) {
	int retval=-1;
	retval=add_label_to_packet(atoi(argv[0]),atoi(argv[1]));
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(	mplsd_add_otunnel_packet	,
	mplsd_add_otunnel_packet_cmd	,
	"add_otunnel_packet iface WORD "	,
	"add_otunnel_packet iface-string "	) {
	retval=add_otunnel_packet(argv[0]);
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}
	
DEFUN(	mplsd_add_label_stack	,
	mplsd_add_label_stack_cmd	,
	"add_label_stack label_key <1-65535> label <0-65535>"	,
	"add_label_stack label_key-int label-int"	) {
	retval=add_label_stack(atoi(argv[0]),atoi(argv[1]));
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}
//end for VPLS technology capability

DEFUN(	mplsadmd_vty_add_label_space	,
	mplsadmd_vty_add_label_space_cmd	,
	"add_label_space interface WORD label_space_no <0-65535>"	,
	"add_label_space interface-string label_space_no-int"	) {
	retval=add_label_space( argv[0], atoi(argv[1]) );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_del_label_space	,
	mplsadmd_vty_del_label_space_cmd	,
	"del_label_space interface WORD"	,
	"del_label_space interface-string"	) {
	retval=del_label_space( argv[0] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_add_fec_to_label	,
	mplsadmd_vty_add_fec_to_label_cmd	,
	"add_fec_to_label table <1-65535> fec WORD label <1-65535> exp <1-65535> iface WORD nh WORD"	,
	"add_fec_to_label table-int fec-string label-int exp-int iface-string nh-string"	) {
	//only for test
	//vty_out (vty, "Down to mplsadmd node%s", VTY_NEWLINE);
	/*int retKey=add_fec_to_label( atoi(argv[0]), argv[1], atoi(argv[2]), atoi(argv[3]), argv[4], argv[5],vty );
	printf("retKey :%d\n",retKey);	
	vty_out(vty,"%d%s",retKey,VTY_NEWLINE);*/
	vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}
	
//not used on rsvpd 
DEFUN(	mplsadmd_vty_del_fec_to_label	,
	mplsadmd_vty_del_fec_to_label_cmd	,
	"del_fec_to_label table <1-65535> fec WORD label <1-65535> exp <1-65535> iface WORD"	,
	"del_fec_to_label table-int fec-string label-int exp-int iface-string"	) {
	/*retval=del_fec_to_label( atoi(argv[0]), argv[1], atoi(argv[2]), atoi(argv[3]), argv[4] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);*/
	vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_add_olabel_exp	,
	mplsadmd_vty_add_olabel_exp_cmd	,
	"add_olabel_exp label <1-65535> exp <0-7> iface WORD nh WORD"	,
	"add_olabel_exp label-int exp-int iface-string nh-string"	) {
	retval=add_olabel_exp( atoi(argv[0]), atoi(argv[1]), argv[2], argv[3] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	//vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_add_olabel_tc	,
	mplsadmd_vty_add_olabel_tc_cmd	,
	"add_olabel_tc label <1-65535> tc <1-65535> iface WORD nh WORD"	,
	"add_olabel_tc label-int tc-int iface-string nh-string"	) {
	retval=add_olabel_tc( atoi(argv[0]), atoi(argv[1]), argv[2], argv[3] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_add_olabel	,
	mplsadmd_vty_add_olabel_cmd	,
	"add_olabel label <1-65535> iface WORD nh WORD"	,
	"add_olabel label-int iface-string nh-string"	) {
	retval=add_olabel( atoi(argv[0]), argv[1], argv[2] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_del_olabel	,
	mplsadmd_vty_del_olabel_cmd	,
	"del_olabel labelkey <1-65535>"	,
	"del_olabel labelkey-int"	) {
	retval=del_olabel( atoi(argv[0]) );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_bind_olabel	,
	mplsadmd_vty_bind_olabel_cmd	,
	"bind_olabel ilabel <1-65535> olabelkey <1-65535> labelspace <0-65535>"	,
	"bind_olabel ilabel-int olabelkey-int labelspace-int"	) {
	retval=bind_olabel( atoi(argv[0]), atoi(argv[1]) ,atoi(argv[2]));
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}
	
//not used on rsvpd 
DEFUN(	mplsadmd_vty_unbind_fec_to_label	,
	mplsadmd_vty_unbind_fec_to_label_cmd	,
	"unbind_fec_to_label table <1-65535> fec WORD label <1-65535> exp <1-65535> iface WORD"	,
	"unbind_fec_to_label table-int fec-string label-int exp-int iface-string"	) {
	/*retval=unbind_fec_to_label( atoi(argv[0]), argv[1], atoi(argv[2]), atoi(argv[3]), argv[4] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);*/
	vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_add_label_to_label	,
	mplsadmd_vty_add_label_to_label_cmd	,
	"add_label_to_label il <0-65535> ol <1-65535> iface WORD nh WORD"	,
	"add_label_to_label il-int ol-int iface-string nh-string"	) {
	retval=add_label_to_label( atoi(argv[0]), atoi(argv[1]), argv[2], argv[3] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	//vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_add_label_to_label_tc	,
	mplsadmd_vty_add_label_to_label_tc_cmd	,
	"add_label_to_label_tc il <1-65535> ol <1-65535> tc <1-65535> iface WORD nh WORD"	,
	"add_label_to_label_tc il-int ol-int tc-int iface-string nh-string"	) {
	retval=add_label_to_label_tc( atoi(argv[0]), atoi(argv[1]), atoi(argv[2]), argv[3], argv[4] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	//vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_del_label_to_label	,
	mplsadmd_vty_del_label_to_label_cmd	,
	"del_label_to_label ilabel <1-65535> okey <1-65535>"	,
	"del_label_to_label ilabel-int okey-int"	) {
	retval=del_label_to_label( atoi(argv[0]), atoi(argv[1]) );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	//vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}

//not used on rsvpd 
DEFUN(	mplsadmd_vty_del_ilabel	,
	mplsadmd_vty_del_ilabel_cmd	,
	"del_ilabel il <1-65535> iexp <1-65535> labelspace <0-65535>"	,
	"del_ilabel il-int iexp-int labelspace-int"	) {
	retval=del_ilabel( atoi(argv[0]), atoi(argv[1]),atoi(argv[2]) );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_add_label_to_ipv4	,
	mplsadmd_vty_add_label_to_ipv4_cmd	,
	"add_label_to_ipv4 il <1-65535>"	,
	"add_label_to_ipv4 il-int"	) {
	retval=add_label_to_ipv4( atoi(argv[0]) );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	//vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_add_label_to_ipv4_setdscp	,
	mplsadmd_vty_add_label_to_ipv4_setdscp_cmd	,
	"add_label_to_ipv4_setdscp il <1-65535>"	,
	"add_label_to_ipv4_setdscp il-int"	) {
	retval=add_label_to_ipv4_setdscp( atoi(argv[0]) );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	//vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_del_label_to_ipv4	,
	mplsadmd_vty_del_label_to_ipv4_cmd	,
	"del_label_to_ipv4 il <1-65535>"	,
	"del_label_to_ipv4 il-int"	) {
	retval=del_label_to_ipv4( atoi(argv[0]) );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	//vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}
//add by here . To suitable for ldpd/impl_mpls.c file
DEFUN(	mplsadmd_vty_add_label_to_ipv4_labelspace ,
	mplsadmd_vty_add_label_to_ipv4_labelspace_cmd	,
	"add_label_to_ipv4_labelspace il <1-65535> label_space_no <0-65535>"	,
	"add_label_to_ipv4_labelspace il-int label_space_no-int"	) {
	/*retval=add_label_to_ipv4_labelspace( atoi(argv[0]), atoi(argv[1]) );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);*/
	vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}
DEFUN(	mplsadmd_vty_del_label_to_ipv4_labelspace	,
	mplsadmd_vty_del_label_to_ipv4_labelspace_cmd	,
	"del_label_to_ipv4_labelspace il <1-65535> label_space_no <0-65535>"	,
	"del_label_to_ipv4_labelspace il-int label_space_no-int"	) {
	/*retval=del_label_to_ipv4_labelspace( atoi(argv[0]), atoi(argv[1]) );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);*/
	vty_out(vty,"%s%s","This command doesn't supported.",VTY_NEWLINE);
	return CMD_SUCCESS;}

//end by here


DEFUN(	mplsadmd_vty_create_tunnel_interface	,
	mplsadmd_vty_create_tunnel_interface_cmd	,
	"create_tunnel_interface mplsiface WORD"	,
	"create_tunnel_interface mplsiface-string"	) {
	retval=create_tunnel_interface( argv[0] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_map_label_tunnel	,
	mplsadmd_vty_map_label_tunnel_cmd	,
	"map_label_tunnel labelref <1-65535> mplsiface WORD"	,
	"map_label_tunnel labelref-int mplsiface-string"	) {
	retval=map_label_tunnel( atoi(argv[0]), argv[1] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	mplsadmd_vty_del_tunnel	,
	mplsadmd_vty_del_tunnel_cmd	,
	"del_tunnel mplsiface WORD"	,
	"del_tunnel mplsiface-string"	) {
	retval=del_tunnel( argv[0] );
	vty_out(vty,"%d%s",retval,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	router_mplsadmd,
	router_mplsadmd_cmd,
	"router mplsadmd",
	"Enable a routing process"
	"MPLSADMD protocol")
{
 vty->node = MPLSADMD_NODE;
 //vty_out (vty, "Down to mplsadmd node%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}

static struct cmd_node mplsadmd_node =
{ MPLSADMD_NODE, "%s(config-mplsadmd)# ", 1 };

void mplsadmd_init(void)
{
install_node( &mplsadmd_node, NULL );
install_default( MPLSADMD_NODE );

//install_element (VIEW_NODE,   &router_mplsadmd_cmd);
//install_element (ENABLE_NODE, &router_mplsadmd_cmd);
install_element (VIEW_NODE, &show_mpls_nhlfe_cmd);
install_element (ENABLE_NODE, &show_mpls_nhlfe_cmd);

install_element (VIEW_NODE, &show_mpls_ilm_cmd);
install_element (ENABLE_NODE, &show_mpls_ilm_cmd);

install_element (VIEW_NODE, &show_mpls_labelspace_cmd);
install_element (ENABLE_NODE, &show_mpls_labelspace_cmd);

install_element (VIEW_NODE, &show_mpls_xc_cmd);
install_element (ENABLE_NODE, &show_mpls_xc_cmd);

install_element (CONFIG_NODE, &router_mplsadmd_cmd);

install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_label_space_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_del_label_space_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_fec_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_del_fec_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_olabel_exp_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_olabel_tc_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_olabel_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_del_olabel_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_bind_olabel_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_unbind_fec_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_label_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_label_to_label_tc_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_del_label_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_del_ilabel_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_label_to_ipv4_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_label_to_ipv4_setdscp_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_del_label_to_ipv4_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_add_label_to_ipv4_labelspace_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_del_label_to_ipv4_labelspace_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_create_tunnel_interface_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_map_label_tunnel_cmd	);
install_element( MPLSADMD_NODE,   &	mplsadmd_vty_del_tunnel_cmd	);

install_element( MPLSADMD_NODE,   &	mplsd_add_label_to_packet_cmd	);
install_element( MPLSADMD_NODE,   &	mplsd_add_otunnel_packet_cmd	);
install_element( MPLSADMD_NODE,   &	mplsd_add_label_stack_cmd	);
}
