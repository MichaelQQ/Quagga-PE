#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "ldp_interface.h"
#include <zebra.h>
#include "zclient.h"
#include "vty.h"
#include "command.h"
#include "table.h"

#include "ldp.h"
#include "ldp_cfg.h"
#include "ldp_vty.h"
#include "ldp_interface.h"
#include "ldp_struct.h"
#include "mpls_struct.h"
#include "mpls_list.h"
#include "ldp_remote_peer.h"
#include "ldp_zebra.h"
#include "ldp_pdu_setup.h"
#include "impl_mpls.h"
#include "ldp_mesg.h"
#include "connect_daemon.h" //add by here
#include "ldp_via_vpnm.h"

int PW_SIGNALING_FLAG;//1: pseudowire signaling, 0: general signaling

int withdraw_pw_process(ldp_global *g, ldp_adj *a, u_int vpn_id, u_long label);
int release_pw_process(ldp_global *g, ldp_adj *a, u_int vpn_id, u_long label);

//void establish_ldp_session(struct sockaddr_in sockaddr)
void establish_ldp_session_here(unsigned long dst_ip)
{
  struct ldp *ldp=ldp_get();
  struct mpls_dest dest;
  struct ldp_remote_peer *rp;
  
  dest.addr.type = MPLS_FAMILY_IPV4;
  //dest.port = ntohs(sockaddr.sin_port);
  //dest.addr.u.ipv4 = ntohl(sockaddr.sin_addr.s_addr);
  dest.addr.u.ipv4 = ntohl(dst_ip);
  dest.port = LDP_PORT;
  //if (ldp_remote_peer_find(ldp,&dest)) {
    //return 0;
  //}
  //printf("%x\n",dst_ip);
  rp = ldp_remote_peer_new(ldp);
  listnode_add(ldp->peer_list, rp);
  ldp_remote_peer_create(rp,&dest);
}

//void stop_ldp_session(struct sockaddr_in sockaddr) //added at 05.06.06
void stop_ldp_session_here(unsigned long dst_ip) //added at 05.06.06
{
  struct ldp *ldp = ldp_get();
  struct mpls_dest dest;
  struct ldp_remote_peer *rp;	
  
  // sockaddr_in -> mpls_dest
  dest.addr.type = MPLS_FAMILY_IPV4;
  //dest.port = ntohs(sockaddr->sin_port);
  //dest.addr.u.ipv4 = ntohl(sockaddr->sin_addr.s_addr);
  dest.addr.u.ipv4 = ntohl(dst_ip);
  dest.port = LDP_PORT;

 if ((rp = ldp_remote_peer_find(ldp,&dest))) {
    listnode_delete(ldp->peer_list, rp);
    ldp_remote_peer_delete(rp);
   ldp_remote_peer_free(rp);
  }
  //return 1;
}
//fail : passive lable or 0; Sucess : Postive pw_label
int verify_vc_state(struct vty *vty,int vc_type,int vpn_id,int label,unsigned long dst_ip){
	
	char	buf[255];
	struct in_addr tmp_addr;
	tmp_addr.s_addr=dst_ip;
	ldp_adj *adj=NULL; 
  ldp_global *global; 
	int flag=0,pw_label=0;
	struct mpls_dest dest;
	struct ldp *ldp=ldp_get();
	
	global=(ldp_global *)ldp->h;
  adj=MPLS_LIST_HEAD(&global->adj);

	dest.addr.type = MPLS_FAMILY_IPV4;
  dest.addr.u.ipv4 = ntohl(dst_ip);
  dest.port = LDP_PORT;
  
  printf("=======ADDRESS: %x\n", dest.addr.u.ipv4); //testing
  printf("======= %x\n",adj->remote_lsr_address.u.ipv4);
   while (adj != NULL && adj->session!=NULL)
   {
     if(adj->remote_lsr_address.u.ipv4==dest.addr.u.ipv4){
        if (adj->session && adj->session->state==LDP_STATE_OPERATIONAL){
          //Peer LDP session is established. 
          flag=1;
            pw_label=send_label_mapping_here(global, adj,vpn_id,tmp_addr);
            return pw_label;
          }
        }
        adj = MPLS_LIST_NEXT(&global->adj, adj, _global);
      }
      if (flag==0)
      {
      	//Peer LDP sesssio not establish.
      	return 0;
      }
}

int withdraw_pw_here(int vc_type,int vpn_id,int label,unsigned long dst_ip){
	int retval=0;//check withdraw process is sucess or fail; sucess : 1 fail :0  
	ldp_adj *adj=NULL; 
  ldp_global *global; 
	struct mpls_dest dest;
	struct ldp *ldp=ldp_get();
	
	global=(ldp_global *)ldp->h;
  adj=MPLS_LIST_HEAD(&global->adj);

	dest.addr.type = MPLS_FAMILY_IPV4;
  dest.addr.u.ipv4 = ntohl(dst_ip);
  dest.port = LDP_PORT;
  while (adj != NULL && adj->session!=NULL)
      {
        //if(adj->session->remote_dest.addr.u.ipv4==dest.addr.u.ipv4){
        if(adj->remote_lsr_address.u.ipv4==dest.addr.u.ipv4){
          if (adj->session && adj->session->state==LDP_STATE_OPERATIONAL)
           retval=withdraw_pw_process(global, adj, vpn_id,label);
           //withdraw_pw_process(global, adj, mesg->u.vi.vpn_id, mesg->u.vi.label);
        }
        adj = MPLS_LIST_NEXT(&global->adj, adj, _global);
      }
   return retval;
}

int withdraw_pw_process(ldp_global *g, ldp_adj *a, u_int vpn_id, u_long label) //05.05.23
{
  mplsLdpLbl_W_R_Msg_t *map=NULL;
  mplsFecElement_t pwid_element;
  struct ldp *ldp=ldp_get();
  char buf[200];//add by here
  int retval;//add by here
  printf("Enter PW withdraw\n");

  pwid_element.pwidEl.pw_tlv=MPLS_PW_ID_FEC;
  pwid_element.pwidEl.flags.mark=0;
  pwid_element.pwidEl.flags.control_word=0;
  pwid_element.pwidEl.flags.pw_type=0x0005;
  pwid_element.pwidEl.pw_info_Len=4; //pw ID+interface parameter
  pwid_element.pwidEl.group_id=vpn_id;
  pwid_element.pwidEl.pw_id=vpn_id;

  if (a->session && a->session->state==LDP_STATE_OPERATIONAL)
  {
    //ReleaseLabelToPool(LDP_POOL_ID, label);//05.06.10 call label manager to release label
    /*release label to pool form lmd*/
    connect_daemon(VTYSH_INDEX_LMD);
    sprintf(buf,"releaseLabelToPool pool_id %d label %d\n",LDP_POOL_ID,label);
    retval=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LMD], buf, stdout);
    printf("Debug msg(releaseLabelToPool) retval:%d\n",retval);
    exit_daemon(VTYSH_INDEX_LMD);
    
    ldp_mesg_prepare(a->session->tx_message, MPLS_LBLWITH_MSGTYPE,
                   g->message_identifier++);
    map=&a->session->tx_message->u.map;
    map->fecTlvExists = 1;
    map->baseMsg.msgLength += setupFecTlv(&map->fecTlv);//setup base header
    map->baseMsg.msgLength += addFecElem2FecTlv(&map->fecTlv,&pwid_element);
    if (ldp_mesg_send_tcp(g, a->session, a->session->tx_message) == MPLS_SUCCESS){
    	return 1;
    	printf("Success!!\n");//testing
    }else{
    	printf("Error\n");//testing
    	return 0;
    }
  }
}

int release_pw_here(int vc_type,int vpn_id,int label,unsigned long dst_ip){
	int retval=0;
	ldp_adj *adj=NULL; 
  ldp_global *global; 
	struct mpls_dest dest;
	struct ldp *ldp=ldp_get();
	
	global=(ldp_global *)ldp->h;
  adj=MPLS_LIST_HEAD(&global->adj);

	dest.addr.type = MPLS_FAMILY_IPV4;
  dest.addr.u.ipv4 = ntohl(dst_ip);
  dest.port = LDP_PORT;
  while (adj != NULL && adj->session!=NULL)
  {
        //if(adj->session->remote_dest.addr.u.ipv4==dest.addr.u.ipv4){
    if(adj->remote_lsr_address.u.ipv4==dest.addr.u.ipv4){
       if (adj->session && adj->session->state==LDP_STATE_OPERATIONAL)
           retval=release_pw_process(global, adj, vpn_id, label);
       }
        adj = MPLS_LIST_NEXT(&global->adj, adj, _global);
  }
  return retval;
}

int release_pw_process(ldp_global *g, ldp_adj *a, u_int vpn_id, u_long label) //add at 05.06.06
{
	
  mplsLdpLbl_W_R_Msg_t *map=NULL;
  mplsFecElement_t pwid_element;
  struct ldp *ldp=ldp_get();

  printf("Enter PW release\n");

  pwid_element.pwidEl.pw_tlv=MPLS_PW_ID_FEC;
  pwid_element.pwidEl.flags.mark=0;
  pwid_element.pwidEl.flags.control_word=0;
  pwid_element.pwidEl.flags.pw_type=0x0005;
  pwid_element.pwidEl.pw_info_Len=4; //pw ID+interface parameter
  pwid_element.pwidEl.group_id=vpn_id;
  pwid_element.pwidEl.pw_id=vpn_id;

  if (a->session && a->session->state==LDP_STATE_OPERATIONAL)
  {
    ldp_mesg_prepare(a->session->tx_message, MPLS_LBLREL_MSGTYPE,
                   g->message_identifier++);
    map=&a->session->tx_message->u.map;
    map->fecTlvExists = 1;
    map->baseMsg.msgLength += setupFecTlv(&map->fecTlv);//setup base header
    map->baseMsg.msgLength += addFecElem2FecTlv(&map->fecTlv,&pwid_element);
    map->genLblTlvExists = 1;
    map->baseMsg.msgLength += setupGenLblTlv(&map->genLblTlv, label);
    if(ldp_mesg_send_tcp(g, a->session, a->session->tx_message) == MPLS_SUCCESS){
    	printf("Success!!\n");//testing
    	return 1;
 		}else{
 			printf("Error\n");//testing
 			return 0;
 		}
  }
}

//return PW label; Success : return lable; fail : return -1;
int send_label_mapping_here(ldp_global *g, ldp_adj *a, u_int vpn_id, struct in_addr ip)
{
	char buf[200];//add by here
  PW_SIGNALING_FLAG=1; //pseudowire signaling
  int label; //testing, after LM OK will be deleted
  mplsLdpLblMapMsg_t *map=NULL;
  mplsFecElement_t pwid_element;

  pwid_element.pwidEl.pw_tlv=MPLS_PW_ID_FEC;
  pwid_element.pwidEl.flags.mark=0;
  pwid_element.pwidEl.flags.control_word=0;
  pwid_element.pwidEl.flags.pw_type=0x0005;
  pwid_element.pwidEl.pw_info_Len=4; //pw ID+interface parameter 
  pwid_element.pwidEl.group_id=vpn_id;
  pwid_element.pwidEl.pw_id=vpn_id;

  if (a->session && a->session->state==LDP_STATE_OPERATIONAL)
  {
    /*
    label=RequestLabelFromPool(LDP_POOL_ID);//testing
    printf("********************LABEL: %d\n",label);
    */
    /*request a new label*/
    connect_daemon(VTYSH_INDEX_LMD);
    sprintf(buf,"requestLabelFromPool pool_id %d",LDP_POOL_ID);
	  label=vtysh_client_execute(&vtysh_client[VTYSH_INDEX_LMD], buf, stdout);
    exit_daemon(VTYSH_INDEX_LMD);
    printf("Get label from LMD :%d\n",label);
    ldp_mesg_prepare(a->session->tx_message, MPLS_LBLMAP_MSGTYPE,
                   g->message_identifier++);
    map=&a->session->tx_message->u.map;
    map->fecTlvExists = 1;
    map->baseMsg.msgLength += setupFecTlv(&map->fecTlv);//setup base header
    map->baseMsg.msgLength += addFecElem2FecTlv(&map->fecTlv,&pwid_element);
    map->genLblTlvExists = 1;
    map->baseMsg.msgLength += setupGenLblTlv(&map->genLblTlv, label);
    if (ldp_mesg_send_tcp(g, a->session, a->session->tx_message) == MPLS_SUCCESS)
    {
			return label;
    }
    else
   // printf("Error\n");
    return -1;
  }
}
