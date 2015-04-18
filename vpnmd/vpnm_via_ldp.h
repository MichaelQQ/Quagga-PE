#define WITHDRAW_IN 0
#define WITHDRAW_OUT 1
#define WITHDRAW_DOIT -1

//add by here 
typedef enum 
 {
  ldpSendHello=0,
  ldpStopHello,
  ldpVCInfo,
  ldpWithdrawPW,
  ldpReleasePW
 }LDP_Command;
 

typedef enum 
 {
  vpnmInPWLabel=0,
  vpnmSessionState=1,
  vpnmRcvLdpWithdrawMsg,
  vpnmRcvLdpReleaseMsg,
  vpnmOutPwLabel
 }VPNM_Command;


int set_in_pw_info(struct vty *vty, int vpn_id,unsigned long dst_ip,int label);
int set_out_pw_info(int vpn_id,unsigned long dst_ip,int label);
int withdraw_pw_info(int vpn_id,unsigned long dst_ip);
int release_pw_info(int vpn_id,unsigned long dst_ip);
int setup_pw_info_here(struct vty *vty, int vpn_id,unsigned long dst_ip,int pw_in_label);
//end by here
