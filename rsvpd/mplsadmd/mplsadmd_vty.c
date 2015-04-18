#include "zebra.h"
#include "command.h"
#include "log.h"
#include "libmpls.h"

DEFUN(	rsvpd_vty_add_label_space	,
	rsvpd_vty_add_label_space_cmd	,
	"add_label_space interface WORD label_space_no <1-65535>"	,
	"add_label_space interface-string label_space_no-int"	) {
	add_label_space( argv[0], atoi(argv[1]) );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_del_label_space	,
	rsvpd_vty_del_label_space_cmd	,
	"del_label_space interface WORD"	,
	"del_label_space interface-string"	) {
	del_label_space( argv[0] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_add_fec_to_label	,
	rsvpd_vty_add_fec_to_label_cmd	,
	"add_fec_to_label table <1-65535> fec WORD label <1-65535> exp <1-65535> iface WORD nh WORD"	,
	"add_fec_to_label table-int fec-string label-int exp-int iface-string nh-string"	) {
	//only for test
	//vty_out (vty, "Down to rsvpd node%s", VTY_NEWLINE);
	int retKey=add_fec_to_label( atoi(argv[0]), argv[1], atoi(argv[2]), atoi(argv[3]), argv[4], argv[5],vty );
	printf("retKey :%d\n",retKey);
	vty_out(vty,"%d%s",retKey,VTY_NEWLINE);
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_del_fec_to_label	,
	rsvpd_vty_del_fec_to_label_cmd	,
	"del_fec_to_label table <1-65535> fec WORD label <1-65535> exp <1-65535> iface WORD"	,
	"del_fec_to_label table-int fec-string label-int exp-int iface-string"	) {
	del_fec_to_label( atoi(argv[0]), argv[1], atoi(argv[2]), atoi(argv[3]), argv[4] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_add_olabel_exp	,
	rsvpd_vty_add_olabel_exp_cmd	,
	"add_olabel_exp label <1-65535> exp <1-65535> iface WORD nh WORD"	,
	"add_olabel_exp label-int exp-int iface-string nh-string"	) {
	add_olabel_exp( atoi(argv[0]), atoi(argv[1]), argv[2], argv[3] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_add_olabel_tc	,
	rsvpd_vty_add_olabel_tc_cmd	,
	"add_olabel_tc label <1-65535> tc <1-65535> iface WORD nh WORD"	,
	"add_olabel_tc label-int tc-int iface-string nh-string"	) {
	add_olabel_tc( atoi(argv[0]), atoi(argv[1]), argv[2], argv[3] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_add_olabel	,
	rsvpd_vty_add_olabel_cmd	,
	"add_olabel label <1-65535> iface WORD nh WORD"	,
	"add_olabel label-int iface-string nh-string"	) {
	add_olabel( atoi(argv[0]), argv[1], argv[2] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_del_olabel	,
	rsvpd_vty_del_olabel_cmd	,
	"del_olabel labelkey <1-65535>"	,
	"del_olabel labelkey-int"	) {
	del_olabel( atoi(argv[0]) );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_bind_olabel	,
	rsvpd_vty_bind_olabel_cmd	,
	"bind_olabel ilabel <1-65535> olabelkey <1-65535>"	,
	"bind_olabel ilabel-int olabelkey-int"	) {
	bind_olabel( atoi(argv[0]), atoi(argv[1]) );
	return CMD_SUCCESS;}
//add by here . To suitable for ldpd/impl_mpls.c file
DEFUN(	rsvpd_vty_unbind_olabel	,
	rsvpd_vty_unbind_olabel_cmd	,
	"unbind_olabel olabel <1-65535> olabelkey <1-65535>"	,
	"unbind_olabel olabel-int olabelkey-int"	) {
	unbind_olabel( atoi(argv[0]), atoi(argv[1]) );
	return CMD_SUCCESS;}
DEFUN(	rsvpd_vty_bind_olabel_labelspace	,
	rsvpd_vty_bind_olabel_labelspace_cmd	,
	"bind_olabel_labelspace ilabel <1-65535> label_space_no <1-65535> olabelkey <1-65535>"	,
	"bind_olabel_labelspace ilabel-int label_space_no-int olabelkey-int"	) {
	bind_olabel_labelspace( atoi(argv[0]), atoi(argv[1]),atoi(argv[2]) );
	return CMD_SUCCESS;}
DEFUN(	rsvpd_vty_unbind_olabel_labelspace	,
	rsvpd_vty_unbind_olabel_labelspace_cmd	,
	"unbind_olabel_labelspace ilabel <1-65535> label_space_no <1-65535> olabelkey <1-65535>"	,
	"unbind_olabel_labelspace ilabel-int label_space_no-int olabelkey-int"	) {
	unbind_olabel_labelspace( atoi(argv[0]), atoi(argv[1]),atoi(argv[2]) );
	return CMD_SUCCESS;}
//end by here

DEFUN(	rsvpd_vty_unbind_fec_to_label	,
	rsvpd_vty_unbind_fec_to_label_cmd	,
	"unbind_fec_to_label table <1-65535> fec WORD label <1-65535> exp <1-65535> iface WORD"	,
	"unbind_fec_to_label table-int fec-string label-int exp-int iface-string"	) {
	unbind_fec_to_label( atoi(argv[0]), argv[1], atoi(argv[2]), atoi(argv[3]), argv[4] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_add_label_to_label	,
	rsvpd_vty_add_label_to_label_cmd	,
	"add_label_to_label il <1-65535> ol <1-65535> iface WORD nh WORD"	,
	"add_label_to_label il-int ol-int iface-string nh-string"	) {
	add_label_to_label( atoi(argv[0]), atoi(argv[1]), argv[2], argv[3] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_add_label_to_label_tc	,
	rsvpd_vty_add_label_to_label_tc_cmd	,
	"add_label_to_label_tc il <1-65535> ol <1-65535> tc <1-65535> iface WORD nh WORD"	,
	"add_label_to_label_tc il-int ol-int tc-int iface-string nh-string"	) {
	add_label_to_label_tc( atoi(argv[0]), atoi(argv[1]), atoi(argv[2]), argv[3], argv[4] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_del_label_to_label	,
	rsvpd_vty_del_label_to_label_cmd	,
	"del_label_to_label ilabel <1-65535> okey <1-65535>"	,
	"del_label_to_label ilabel-int okey-int"	) {
	del_label_to_label( atoi(argv[0]), atoi(argv[1]) );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_del_ilabel	,
	rsvpd_vty_del_ilabel_cmd	,
	"del_ilabel il <1-65535> iexp <1-65535>"	,
	"del_ilabel il-int iexp-int"	) {
	del_ilabel( atoi(argv[0]), atoi(argv[1]) );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_add_label_to_ipv4	,
	rsvpd_vty_add_label_to_ipv4_cmd	,
	"add_label_to_ipv4 il <1-65535>"	,
	"add_label_to_ipv4 il-int"	) {
	add_label_to_ipv4( atoi(argv[0]) );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_add_label_to_ipv4_setdscp	,
	rsvpd_vty_add_label_to_ipv4_setdscp_cmd	,
	"add_label_to_ipv4_setdscp il <1-65535>"	,
	"add_label_to_ipv4_setdscp il-int"	) {
	add_label_to_ipv4_setdscp( atoi(argv[0]) );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_del_label_to_ipv4	,
	rsvpd_vty_del_label_to_ipv4_cmd	,
	"del_label_to_ipv4 il <1-65535>"	,
	"del_label_to_ipv4 il-int"	) {
	del_label_to_ipv4( atoi(argv[0]) );
	return CMD_SUCCESS;}
//add by here . To suitable for ldpd/impl_mpls.c file
DEFUN(	rsvpd_vty_add_label_to_ipv4_labelspace ,
	rsvpd_vty_add_label_to_ipv4_labelspace_cmd	,
	"add_label_to_ipv4_labelspace il <1-65535> label_space_no <0-65535>"	,
	"add_label_to_ipv4_labelspace il-int label_space_no-int"	) {
	add_label_to_ipv4_labelspace( atoi(argv[0]), atoi(argv[1]) );
	return CMD_SUCCESS;}
DEFUN(	rsvpd_vty_del_label_to_ipv4_labelspace	,
	rsvpd_vty_del_label_to_ipv4_labelspace_cmd	,
	"del_label_to_ipv4_labelspace il <1-65535> label_space_no <0-65535>"	,
	"del_label_to_ipv4_labelspace il-int label_space_no-int"	) {
	del_label_to_ipv4_labelspace( atoi(argv[0]), atoi(argv[1]) );
	return CMD_SUCCESS;}

//end by here


DEFUN(	rsvpd_vty_create_tunnel_interface	,
	rsvpd_vty_create_tunnel_interface_cmd	,
	"create_tunnel_interface rsvpiface WORD"	,
	"create_tunnel_interface rsvpiface-string"	) {
	create_tunnel_interface( argv[0] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_map_label_tunnel	,
	rsvpd_vty_map_label_tunnel_cmd	,
	"map_label_tunnel labelref <1-65535> rsvpiface WORD"	,
	"map_label_tunnel labelref-int rsvpiface-string"	) {
	map_label_tunnel( atoi(argv[0]), argv[1] );
	return CMD_SUCCESS;}

DEFUN(	rsvpd_vty_del_tunnel	,
	rsvpd_vty_del_tunnel_cmd	,
	"del_tunnel rsvpiface WORD"	,
	"del_tunnel rsvpiface-string"	) {
	del_tunnel( argv[0] );
	return CMD_SUCCESS;}

DEFUN(	router_rsvpadmd,
	router_rsvpadmd_cmd,
	"router rsvpadmd",
	"Enable a routing process"
	"MPLSADMD protocol")
{
 vty->node = MPLSADMD_NODE;
 //vty_out (vty, "Down to mplsadmd node%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}

static struct cmd_node rsvpadmd_node =
{ MPLSADMD_NODE, "%s(config-rsvpadmd)# ", 1 };

void rsvpadmd_init(void)
{
install_node( &rsvpadmd_node, NULL );
install_default( MPLSADMD_NODE );

//install_element (VIEW_NODE,   &router_rsvpadmd_cmd);
//install_element (ENABLE_NODE, &router_rsvpadmd_cmd);
  install_element (CONFIG_NODE, &router_rsvpadmd_cmd);

install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_label_space_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_del_label_space_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_fec_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_del_fec_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_olabel_exp_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_olabel_tc_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_olabel_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_del_olabel_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_bind_olabel_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_unbind_olabel_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_bind_olabel_labelspace_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_unbind_olabel_labelspace_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_unbind_fec_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_label_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_label_to_label_tc_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_del_label_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_del_ilabel_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_label_to_ipv4_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_label_to_ipv4_setdscp_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_del_label_to_ipv4_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_add_label_to_ipv4_labelspace_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_del_label_to_ipv4_labelspace_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_create_tunnel_interface_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_map_label_tunnel_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpadmd_vty_del_tunnel_cmd	);
}
