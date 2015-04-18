
typedef enum 
 {
  rsvpSetupTunnel,
  rsvpReleaseTunnel,
  rsvpWithdrawTunnel
 }RSVP_Command;
 
typedef enum 
 {
  SEND_PATH_MSG,
  SEND_RESERVE_MSG,
  WITHDRAW_TUNNEL,
  RELEASE_TUNNEL
 }RSVP_New_Command;
 
typedef enum 
 {
  vpnmInTunnelLable,
  vpnmOutTunnelLable,
  vpnmRcvPathtearMsg,
  vpnmRcvResvtearMsg,
  vpnmReleaseTunnel
 }VPNM2RSVP_Command;
 
 
int add_in_tunnel_label(int label,char * in_if,unsigned long dst_ip,int lsp_id);
//not ready for use ; the next_hop_ip is not ready
int add_out_tunnel_label(int label,char * out_if,unsigned long dst_ip,unsigned long next_hop_ip,int nhlfe_key,int lsp_id);
int pro_pathtear_msg(unsigned long dst_ip);
int pro_resvtear_msg(unsigned long dst_ip);

int release_tunnel(int lsp_id,unsigned long dst_ip);

int del_incoming_data_plane_here(vpn_entry *vpn,unsigned long dst_ip);
int del_outgoing_data_plane_here(vpn_entry *vpn,unsigned long dst_ip);
