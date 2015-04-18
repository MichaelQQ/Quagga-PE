typedef enum 
 {
  vpnmInTunnelLable,
  vpnmOutTunnelLable,
  vpnmRcvPathtearMsg,
  vpnmRcvResvtearMsg,
  vpnmReleaseTunnel 
 }VPNM2RSVP_Command;

typedef enum{
	SEND_PATH_MSG,
	SEND_RESERVE_MSG,
	WITHDRAW_TUNNEL,
	RELEASE_TUNNEL
}RSVP_CMD;
