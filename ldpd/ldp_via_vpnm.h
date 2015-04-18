//add by here 
typedef enum 
 {
  ldpSendHello,
  ldpStopHello,
  ldpVCInfo,
  ldpWithdrawPW,
  ldpReleasePW
 }LDP_Command;
 
 typedef enum 
 {
  vpnmInPWLabel,
  vpnmSessionState,
  vpnmRcvLdpWithdrawMsg,
  vpnmRcvLdpReleaseMsg,
  vpnmOutPwLabel
 }VPNM_Command;
//end by here