
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */  
  
#ifndef _PDU_SETUP_
#define _PDU_SETUP_
  
#include "ldp_struct.h"
#include "ldp_nortel.h"
void setBaseMsgId(mplsLdpMsg_t * baseMsg, unsigned int msgId);
void setupBaseMsg(mplsLdpMsg_t * baseMsg, unsigned int type, int uBit,

  unsigned int msgId);
int setupChpTlv(mplsLdpChpTlv_t * chpTlv, int target, int request, int res,

  int holdTime);
int setupPinningTlv(mplsLdpPinningTlv_t * pinningTlv, int pBit, int res);
int setupResClassTlv(mplsLdpResClsTlv_t * resClsTlv, unsigned int rsCls);
int setupPreemptTlv(mplsLdpPreemptTlv_t * preemptTlv, unsigned char setPrio,
  unsigned char holdPrio, unsigned short res);
int addErHop2ErHopTvl(mplsLdpErTlv_t * erHopTlv, mplsLdpErHop_t * erHop,
  unsigned short type); int setupErHopTlv(mplsLdpErTlv_t * erHopTlv);
int setupTrAddrTlv(mplsLdpTrAdrTlv_t * trAddrTlv, unsigned int trAddr);
int setupCsnTlv(mplsLdpCsnTlv_t * csnTlv, unsigned int confSeqNum);
int setupCspTlv(mplsLdpCspTlv_t * cspTlv, uint16_t keepalive,
  uint8_t adv_discp, uint8_t loop, uint8_t pvl, uint16_t mtu,
  uint32_t remote_lsraddr, uint16_t remote_labelspace, uint32_t res);
int addLblRng2AspTlv(mplsLdpAspTlv_t * aspTlv, unsigned int minvpi,
  unsigned int minvci, unsigned int maxvpi, unsigned int maxvci);
int addLblRng2FspTlv(mplsLdpFspTlv_t * fspTlv, unsigned int resmin,
  unsigned int len, unsigned int mindlci, unsigned int resmax,

  unsigned int maxdlci);
int setupAspTlv(mplsLdpAspTlv_t * aspTlv, uint8_t merge, uint8_t direction);
int setupFspTlv(mplsLdpFspTlv_t * fspTlv, uint8_t merge, uint8_t direction);
int setupFecTlv(mplsLdpFecTlv_t * fecTlv);


#if 0
  mplsFecElement_t * createFecElemFromFecType(struct mpls_fec *fec);

mplsFecElement_t * createFecElemFromRoute(routeT * r);
void copyLabelType2MapLabelTlv(struct mpls_label *label,

  mplsLdpLblMapMsg_t * lblMap);
void copyAtmLblTlv2MplsLabel(mplsLdpAtmLblTlv_t * atmLblTlv,

  struct mpls_label *label);
void copyFrLblTlv2MplsLabel(mplsLdpFrLblTlv_t * frLblTlv,

  struct mpls_label *label);
void copyGenLblTlv2MplsLabel(mplsLdpGenLblTlv_t * genLblTlv,

  struct mpls_label *label); 
#endif /*  */
int addFecElem2FecTlv(mplsLdpFecTlv_t * fecTlv, mplsFecElement_t * elem);
int setupAtmLblTlv(mplsLdpAtmLblTlv_t * atmLblTlv, int res, int v,
  unsigned int vpi, unsigned int vci);
int setupFrLblTlv(mplsLdpFrLblTlv_t * frLblTlv, int res, int len,

  unsigned int dlci);
int setupGenLblTlv(mplsLdpGenLblTlv_t * genLblTlv, int label);
int setupHopCountTlv(mplsLdpHopTlv_t * hopCountTlv, unsigned int hopCount);
int setupPathTlv(mplsLdpPathTlv_t * pathTlv);
int addLsrId2PathTlv(mplsLdpPathTlv_t * pathTlv, unsigned int lsrId);
int setupAddrTlv(mplsLdpAdrTlv_t * addrTlv);
int addAddrElem2AddrTlv(mplsLdpAdrTlv_t * addrTlv, unsigned int addr);
int setupStatusTlv(mplsLdpStatusTlv_t * statTlv, int fatal, int forward,
  int status, unsigned int msgId, int msgType);
int setupExStatusTlv(mplsLdpExStatusTlv_t * exStatus, unsigned int value);
int setupRetPduTlv(mplsLdpRetPduTlv_t * retPduTvl, unsigned int len,
  mplsLdpHeader_t * hdr, void *data);
int setupRetMsgTlv(mplsLdpRetMsgTlv_t * retMsgTlv, unsigned type, unsigned len,

  void *data);
int setupLspidTlv(mplsLdpLspIdTlv_t * lspidTlv, int res,
  unsigned int localCrlspId, unsigned int routerId);
int setupTrafficTlv(mplsLdpTrafficTlv_t * trafficTlv, unsigned char freq,
  unsigned char res, unsigned char weight, float pdr, float pbs, float cdr,
  float cbs, float ebs);
int setupLblMsgIdTlv(mplsLdpLblMsgIdTlv_t * lblMsgIdTlv, unsigned int msgId);


#endif /*  */
