
/*
 *  Copyright (C) James R. Leu 2000
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */  
  
#include "ldp_struct.h"
#include "ldp_pdu_setup.h"

void setBaseMsgId(mplsLdpMsg_t * baseMsg, unsigned int msgId)
{
  baseMsg->msgId = msgId;
}

void setupBaseMsg(mplsLdpMsg_t * baseMsg, unsigned int type, int uBit,
  unsigned int msgId)
{
  baseMsg->flags.flags.msgType = type;
  baseMsg->flags.flags.uBit = uBit;
  baseMsg->msgLength = MPLS_MSGIDFIXLEN;
  setBaseMsgId(baseMsg, msgId);
}

int setupChpTlv(mplsLdpChpTlv_t * chpTlv, int target, int request, int res,
  int holdTime)
{
  chpTlv->baseTlv.flags.flags.tBit = MPLS_CHP_TLVTYPE;
  chpTlv->baseTlv.flags.flags.uBit = 0;
  chpTlv->baseTlv.flags.flags.fBit = 0;
  chpTlv->baseTlv.length = MPLS_CHPFIXLEN;
  chpTlv->flags.flags.target = target;
  chpTlv->flags.flags.request = request;
  chpTlv->flags.flags.res = res;
  chpTlv->holdTime = holdTime;
  return MPLS_TLVFIXLEN + MPLS_CHPFIXLEN;
}

int setupPinningTlv(mplsLdpPinningTlv_t * pinningTlv, int pBit, int res)
{
  pinningTlv->baseTlv.flags.flags.tBit = MPLS_PINNING_TLVTYPE;
  pinningTlv->baseTlv.flags.flags.uBit = 0;
  pinningTlv->baseTlv.flags.flags.fBit = 0;
  pinningTlv->baseTlv.length = 4;
  pinningTlv->flags.flags.pBit = pBit;
  pinningTlv->flags.flags.res = res;
  return 4 + MPLS_TLVFIXLEN;
}

int setupResClassTlv(mplsLdpResClsTlv_t * resClsTlv, unsigned int rsCls)
{
  resClsTlv->baseTlv.flags.flags.tBit = MPLS_RESCLASS_TLVTYPE;
  resClsTlv->baseTlv.flags.flags.uBit = 0;
  resClsTlv->baseTlv.flags.flags.fBit = 0;
  resClsTlv->baseTlv.length = 4;
  resClsTlv->rsCls = rsCls;
  return 4 + MPLS_TLVFIXLEN;
}

int setupPreemptTlv(mplsLdpPreemptTlv_t * preemptTlv, unsigned char setPrio,
  unsigned char holdPrio, unsigned short res)
{
  preemptTlv->baseTlv.flags.flags.tBit = MPLS_PREEMPT_TLVTYPE;
  preemptTlv->baseTlv.flags.flags.uBit = 0;
  preemptTlv->baseTlv.flags.flags.fBit = 0;
  preemptTlv->baseTlv.length = MPLS_PREEMPTTLV_FIXLEN;
  preemptTlv->setPrio = setPrio;
  preemptTlv->holdPrio = holdPrio;
  preemptTlv->res = res;
  return MPLS_PREEMPTTLV_FIXLEN + MPLS_TLVFIXLEN;
}

int addErHop2ErHopTvl(mplsLdpErTlv_t * erHopTlv, mplsLdpErHop_t * erHop,
  unsigned short type)
{
  int num = erHopTlv->numberErHops;
  int result = 0;

  memcpy(&(erHopTlv->erHopArray[num]), erHop, sizeof(mplsLdpErHop_t));
  erHopTlv->erHopTypes[num] = type;
  erHopTlv->numberErHops++;
  switch (type) {
    case MPLS_ERHOP_IPV4_TLVTYPE:
      result = MPLS_ERHOP_IPV4_FIXLEN;
      break;
    case MPLS_ERHOP_IPV6_TLVTYPE:
      result = MPLS_ERHOP_IPV6_FIXLEN;
      break;
    case MPLS_ERHOP_AS_TLVTYPE:
      result = MPLS_ERHOP_AS_FIXLEN;
      break;
    case MPLS_ERHOP_LSPID_TLVTYPE:
      result = MPLS_ERHOP_LSPID_FIXLEN;
      break;
  }
  return result + MPLS_TLVFIXLEN;
}

int setupErHopTlv(mplsLdpErTlv_t * erHopTlv)
{
  erHopTlv->baseTlv.flags.flags.tBit = MPLS_ERHOP_IPV4_TLVTYPE;
  erHopTlv->baseTlv.flags.flags.uBit = 0;
  erHopTlv->baseTlv.flags.flags.fBit = 0;
  erHopTlv->baseTlv.length = 0;
  return MPLS_TLVFIXLEN;
}

int setupTrAddrTlv(mplsLdpTrAdrTlv_t * trAddrTlv, unsigned int trAddr)
{
  trAddrTlv->baseTlv.flags.flags.tBit = MPLS_TRADR_TLVTYPE;
  trAddrTlv->baseTlv.flags.flags.uBit = 0;
  trAddrTlv->baseTlv.flags.flags.fBit = 0;
  trAddrTlv->baseTlv.length = MPLS_TRADRFIXLEN;
  trAddrTlv->address = trAddr;
  return MPLS_TRADRFIXLEN + MPLS_TLVFIXLEN;
}

int setupCsnTlv(mplsLdpCsnTlv_t * csnTlv, unsigned int confSeqNum)
{
  csnTlv->baseTlv.flags.flags.tBit = MPLS_CSN_TLVTYPE;
  csnTlv->baseTlv.flags.flags.uBit = 0;
  csnTlv->baseTlv.flags.flags.fBit = 0;
  csnTlv->baseTlv.length = MPLS_CSNFIXLEN;
  csnTlv->seqNumber = confSeqNum;
  return MPLS_CSNFIXLEN + MPLS_TLVFIXLEN;
}

int setupCspTlv(mplsLdpCspTlv_t * cspTlv, uint16_t keepalive,
  uint8_t adv_discp, uint8_t loop, uint8_t pvl, uint16_t mtu,
  uint32_t remote_lsraddr, uint16_t remote_labelspace, uint32_t res)
{
  cspTlv->baseTlv.flags.flags.tBit = MPLS_CSP_TLVTYPE;
  cspTlv->baseTlv.flags.flags.uBit = 0;
  cspTlv->baseTlv.flags.flags.fBit = 0;
  cspTlv->baseTlv.length = MPLS_CSPFIXLEN;
  cspTlv->protocolVersion = 1;
  cspTlv->holdTime = keepalive;
  cspTlv->flags.flags.lad = adv_discp;
  cspTlv->flags.flags.ld = loop;
  cspTlv->flags.flags.res = res;
  cspTlv->flags.flags.pvl = pvl;
  cspTlv->maxPduLen = mtu;
  cspTlv->rcvLsrAddress = remote_lsraddr;
  cspTlv->rcvLsId = remote_labelspace;
  return MPLS_CSPFIXLEN + MPLS_TLVFIXLEN;
}

int addLblRng2AspTlv(mplsLdpAspTlv_t * aspTlv, unsigned int minvpi,
  unsigned int minvci, unsigned int maxvpi, unsigned int maxvci)
{
  int num = aspTlv->baseTlv.length / MPLS_ASPFIXLEN;

  aspTlv->baseTlv.length += MPLS_ASPFIXLEN;
  aspTlv->lblRngList[num].flags.flags.res1 = 0;
  aspTlv->lblRngList[num].flags.flags.minVpi = minvpi;
  aspTlv->lblRngList[num].flags.flags.minVci = minvci;
  aspTlv->lblRngList[num].flags.flags.res2 = 0;
  aspTlv->lblRngList[num].flags.flags.maxVpi = maxvpi;
  aspTlv->lblRngList[num].flags.flags.maxVci = maxvci;
  return MPLS_ASPFIXLEN;
}

int addLblRng2FspTlv(mplsLdpFspTlv_t * fspTlv, unsigned int resmin,
  unsigned int len, unsigned int mindlci, unsigned int resmax,
  unsigned int maxdlci)
{
  int num = fspTlv->baseTlv.length / MPLS_FSPFIXLEN;

  fspTlv->baseTlv.length += MPLS_FSPFIXLEN;
  fspTlv->lblRngList[num].flags.flags.res_min = resmin;
  fspTlv->lblRngList[num].flags.flags.len = len;
  fspTlv->lblRngList[num].flags.flags.minDlci = mindlci;
  fspTlv->lblRngList[num].flags.flags.res_max = resmax;
  fspTlv->lblRngList[num].flags.flags.maxDlci = maxdlci;
  return MPLS_FSPFIXLEN;
}

int setupAspTlv(mplsLdpAspTlv_t * aspTlv, uint8_t merge, uint8_t direction)
{
  aspTlv->baseTlv.flags.flags.tBit = MPLS_ASP_TLVTYPE;
  aspTlv->baseTlv.flags.flags.uBit = 0;
  aspTlv->baseTlv.flags.flags.fBit = 0;
  aspTlv->flags.flags.dir = direction;
  aspTlv->flags.flags.mergeType = merge;
  aspTlv->baseTlv.length = 0;
  return MPLS_TLVFIXLEN;
}

int setupFspTlv(mplsLdpFspTlv_t * fspTlv, uint8_t merge, uint8_t direction)
{
  fspTlv->baseTlv.flags.flags.tBit = MPLS_FSP_TLVTYPE;
  fspTlv->baseTlv.flags.flags.uBit = 0;
  fspTlv->baseTlv.flags.flags.fBit = 0;
  fspTlv->flags.flags.dir = direction;
  fspTlv->flags.flags.mergeType = merge;
  fspTlv->baseTlv.length = 0;
  return MPLS_TLVFIXLEN;
}

int setupFecTlv(mplsLdpFecTlv_t * fecTlv)
{
  fecTlv->baseTlv.flags.flags.tBit = MPLS_FEC_TLVTYPE;
  fecTlv->baseTlv.flags.flags.uBit = 0;
  fecTlv->baseTlv.flags.flags.fBit = 0;
  fecTlv->baseTlv.length = 0;
  fecTlv->wcElemExists = 0;
  fecTlv->numberFecElements = 0;
  return MPLS_TLVFIXLEN;
}


#if 0
  mplsFecElement_t * createFecElemFromFecType(struct mpls_fec * fec)
{
  mplsFecElement_t * fecElem =
    (mplsFecElement_t *) malloc(sizeof(mplsFecElement_t));
  fecElem->addressEl.type = MPLS_PREFIX_FEC;
  fecElem->addressEl.addressFam = 1;
  fecElem->addressEl.preLen = fec->len;
  fecElem->addressEl.address = fec->prefix;
  return fecElem;
}

mplsFecElement_t * createFecElemFromRoute(routeT * r)
{
  mplsFecElement_t * fecElem = 
    (mplsFecElement_t *) malloc(sizeof(mplsFecElement_t));
  memset(fecElem, 0, sizeof(mplsFecElement_t));
  fecElem->addressEl.type = MPLS_PREFIX_FEC;
  fecElem->addressEl.addressFam = 1;
  fecElem->addressEl.preLen = r->len;
  fecElem->addressEl.address = r->prefix;
  return fecElem;
}


#endif /*  */
int addFecElem2FecTlv(mplsLdpFecTlv_t * fecTlv, mplsFecElement_t * elem)
{
  int num = fecTlv->numberFecElements;
  int size = 0;

  switch (elem->addressEl.type) {
    case MPLS_PREFIX_FEC:
    case MPLS_HOSTADR_FEC:
      size = elem->addressEl.preLen / 8;
      if (elem->addressEl.preLen % 8)
        size++;
      size += 4;
      break;
    case MPLS_CRLSP_FEC:
      size = 4;
      break;
    case MPLS_PW_ID_FEC: //add by timothy
      size=elem->pwidEl.pw_info_Len+8;
      // 8=vc_tlv + vc_type + length + group_id
      break; 
  }
  fecTlv->baseTlv.length += size;
  memcpy(&(fecTlv->fecElArray[num]), elem, sizeof(mplsFecElement_t));
  fecTlv->fecElemTypes[num] = elem->addressEl.type;
  fecTlv->numberFecElements++;
  return size;
}


#if 0
void copyLabelType2MapLabelTlv(struct mpls_label *label,
  mplsLdpLblMapMsg_t * lblMap)
{
  switch (label->ml_type) {
    case MPLS_LABEL_ATM:
      lblMap->baseMsg.msgLength +=
        setupAtmLblTlv(&(lblMap->atmLblTlv), 0, 0, label->u.ml_atm.mla_vpi,
        label->u.ml_atm.mla_vci); lblMap->atmLblTlvExists = 1;
      lblMap->genLblTlvExists = 0;
      lblMap->frLblTlvExists = 0;
      break;
    case MPLS_LABEL_GEN:
      lblMap->baseMsg.msgLength +=
        setupGenLblTlv(&(lblMap->genLblTlv), label->u.ml_gen);
      lblMap->atmLblTlvExists = 0;
      lblMap->genLblTlvExists = 1;
      lblMap->frLblTlvExists = 0;
      break;
    case MPLS_LABEL_FR:
      lblMap->baseMsg.msgLength +=
        setupFrLblTlv(&(lblMap->frLblTlv), 0, 0, label->u.ml_fr);
      lblMap->atmLblTlvExists = 0;
      lblMap->genLblTlvExists = 0;
      lblMap->frLblTlvExists = 1;
      break;
    default:
      LDP_PRINT(g->user_data, "invalid label type\n");
      break;
  }
}
void copyAtmLblTlv2MplsLabel(mplsLdpAtmLblTlv_t * atmLblTlv,
  struct mpls_label *label)
{
  label->ml_type = MPLS_LABEL_ATM;
  label->u.ml_atm.mla_vpi = atmLblTlv->flags.flags.vpi;
  label->u.ml_atm.mla_vci = atmLblTlv->vci;
}


#endif /*  */

int setupAtmLblTlv(mplsLdpAtmLblTlv_t * atmLblTlv, int res, int v,
  unsigned int vpi, unsigned int vci)
{
  atmLblTlv->baseTlv.flags.flags.tBit = MPLS_ATMLBL_TLVTYPE;
  atmLblTlv->baseTlv.flags.flags.uBit = 0;
  atmLblTlv->baseTlv.flags.flags.fBit = 0;
  atmLblTlv->baseTlv.length = MPLS_LBLFIXLEN;
  atmLblTlv->flags.flags.res = res;
  atmLblTlv->flags.flags.v = v;
  atmLblTlv->flags.flags.vpi = vpi;
  atmLblTlv->vci = vci;
  return MPLS_LBLFIXLEN + MPLS_TLVFIXLEN;
}


#if 0
void copyFrLblTlv2MplsLabel(mplsLdpFrLblTlv_t * frLblTlv,
  struct mpls_label *label)
{
  label->ml_type = MPLS_LABEL_FR;
  label->u.ml_fr = frLblTlv->flags.flags.dlci;
}


#endif /*  */

int setupFrLblTlv(mplsLdpFrLblTlv_t * frLblTlv, int res, int len,
  unsigned int dlci)
{
  frLblTlv->baseTlv.flags.flags.tBit = MPLS_FRLBL_TLVTYPE;
  frLblTlv->baseTlv.flags.flags.uBit = 0;
  frLblTlv->baseTlv.flags.flags.fBit = 0;
  frLblTlv->baseTlv.length = MPLS_LBLFIXLEN;
  frLblTlv->flags.flags.res = res;
  frLblTlv->flags.flags.len = len;
  frLblTlv->flags.flags.dlci = dlci;
  return MPLS_LBLFIXLEN + MPLS_TLVFIXLEN;
}


#if 0
void copyGenLblTlv2MplsLabel(mplsLdpGenLblTlv_t * genLblTlv,
  struct mpls_label *label)
{
  label->ml_type = MPLS_LABEL_GEN;
  label->u.ml_gen = genLblTlv->label;
}


#endif /*  */

int setupGenLblTlv(mplsLdpGenLblTlv_t * genLblTlv, int label)
{
  genLblTlv->baseTlv.flags.flags.tBit = MPLS_GENLBL_TLVTYPE;
  genLblTlv->baseTlv.flags.flags.uBit = 0;
  genLblTlv->baseTlv.flags.flags.fBit = 0;
  genLblTlv->baseTlv.length = MPLS_LBLFIXLEN;
  genLblTlv->label = label;
  return MPLS_LBLFIXLEN + MPLS_TLVFIXLEN;
}

int setupHopCountTlv(mplsLdpHopTlv_t * hopCountTlv, unsigned int hopCount)
{
  hopCountTlv->baseTlv.flags.flags.tBit = MPLS_HOPCOUNT_TLVTYPE;
  hopCountTlv->baseTlv.flags.flags.uBit = 0;
  hopCountTlv->baseTlv.flags.flags.fBit = 0;
  hopCountTlv->baseTlv.length = MPLS_HOPCOUNTFIXLEN;
  hopCountTlv->hcValue = hopCount;
  return MPLS_HOPCOUNTFIXLEN + MPLS_TLVFIXLEN;
}

int setupPathTlv(mplsLdpPathTlv_t * pathTlv)
{
  pathTlv->baseTlv.flags.flags.tBit = MPLS_PATH_TLVTYPE;
  pathTlv->baseTlv.flags.flags.uBit = 0;
  pathTlv->baseTlv.flags.flags.fBit = 0;
  pathTlv->baseTlv.length = 0;
  return MPLS_TLVFIXLEN;
}

int addLsrId2PathTlv(mplsLdpPathTlv_t * pathTlv, unsigned int lsrId)
{
  int num = pathTlv->baseTlv.length / sizeof(unsigned int);
  pathTlv->baseTlv.length += sizeof(unsigned int);

  pathTlv->lsrId[num] = lsrId;
  return sizeof(unsigned int);
}

int setupAddrTlv(mplsLdpAdrTlv_t * addrTlv)
{
  addrTlv->baseTlv.flags.flags.tBit = MPLS_ADDRLIST_TLVTYPE;
  addrTlv->baseTlv.flags.flags.uBit = 0;
  addrTlv->baseTlv.flags.flags.fBit = 0;
  addrTlv->baseTlv.length = MPLS_ADDFAMFIXLEN;
  addrTlv->addrFamily = 1;
  return MPLS_TLVFIXLEN + MPLS_ADDFAMFIXLEN;
}

int addAddrElem2AddrTlv(mplsLdpAdrTlv_t * addrTlv, unsigned int addr)
{
  int num = (addrTlv->baseTlv.length - MPLS_ADDFAMFIXLEN) / MPLS_IPv4LEN;

  addrTlv->address[num] = addr;
  addrTlv->baseTlv.length += MPLS_IPv4LEN;
  return MPLS_IPv4LEN;
}

int setupStatusTlv(mplsLdpStatusTlv_t * statTlv, int fatal, int forward,
  int status, unsigned int msgId, int msgType)
{
  statTlv->baseTlv.flags.flags.tBit = MPLS_NOT_ST_TLVTYPE;
  statTlv->baseTlv.flags.flags.uBit = 0;
  statTlv->baseTlv.flags.flags.fBit = 0;
  statTlv->baseTlv.length = MPLS_STATUSFIXLEN;
  statTlv->flags.flags.error = fatal;
  statTlv->flags.flags.forward = forward;
  statTlv->flags.flags.status = status;
  statTlv->msgId = msgId;
  statTlv->msgType = msgType;
  return MPLS_STATUSFIXLEN + MPLS_TLVFIXLEN;
}

int setupExStatusTlv(mplsLdpExStatusTlv_t * exStatus, unsigned int value)
{
  exStatus->baseTlv.flags.flags.tBit = MPLS_NOT_ES_TLVTYPE;
  exStatus->baseTlv.flags.flags.uBit = 0;
  exStatus->baseTlv.flags.flags.fBit = 0;
  exStatus->baseTlv.length = MPLS_EXSTATUSLEN;
  exStatus->value = value;
  return MPLS_EXSTATUSLEN + MPLS_TLVFIXLEN;
}

int setupRetPduTlv(mplsLdpRetPduTlv_t * retPduTvl, unsigned int len,
  mplsLdpHeader_t * hdr, void *data)
{
  retPduTvl->baseTlv.flags.flags.tBit = MPLS_NOT_RP_TLVTYPE;
  retPduTvl->baseTlv.flags.flags.uBit = 0;
  retPduTvl->baseTlv.flags.flags.fBit = 0;
  retPduTvl->baseTlv.length = MPLS_LDP_HDRSIZE + len;
  memcpy(&(retPduTvl->headerTlv), hdr, MPLS_LDP_HDRSIZE);
  memcpy(retPduTvl->data, data, len);
  return MPLS_LDP_HDRSIZE + len + MPLS_TLVFIXLEN;
}

int setupRetMsgTlv(mplsLdpRetMsgTlv_t * retMsgTlv, unsigned type,
  unsigned len, void *data)
{
  retMsgTlv->baseTlv.flags.flags.tBit = MPLS_NOT_RM_TLVTYPE;
  retMsgTlv->baseTlv.flags.flags.uBit = 0;
  retMsgTlv->baseTlv.flags.flags.fBit = 0;
  retMsgTlv->baseTlv.length = len;
  retMsgTlv->msgType = type;
  retMsgTlv->msgLength = 4 + len;
  memcpy(retMsgTlv->data, data, len);
  return 4 + len + MPLS_TLVFIXLEN;
}

int setupLspidTlv(mplsLdpLspIdTlv_t * lspidTlv, int res,
  unsigned int localCrlspId, unsigned int routerId)
{
  lspidTlv->baseTlv.flags.flags.tBit = MPLS_LSPID_TLVTYPE;
  lspidTlv->baseTlv.flags.flags.uBit = 0;
  lspidTlv->baseTlv.flags.flags.fBit = 0;
  lspidTlv->baseTlv.length = MPLS_LSPIDTLV_FIXLEN;
  lspidTlv->res = res;
  lspidTlv->localCrlspId = localCrlspId;
  lspidTlv->routerId = routerId;
  return MPLS_LSPIDTLV_FIXLEN + MPLS_TLVFIXLEN;
}

int setupTrafficTlv(mplsLdpTrafficTlv_t * trafficTlv, unsigned char freq,
  unsigned char res, unsigned char weight, float pdr, float pbs, float cdr,
  float cbs, float ebs)
{
  trafficTlv->baseTlv.flags.flags.tBit = MPLS_TRAFFIC_TLVTYPE;
  trafficTlv->baseTlv.flags.flags.uBit = 0;
  trafficTlv->baseTlv.flags.flags.fBit = 0;
  trafficTlv->baseTlv.length = 0;
  trafficTlv->flags.flags.res = 0;
  trafficTlv->flags.flags.f6Bit = 0;
  trafficTlv->flags.flags.f5Bit = 0;
  trafficTlv->flags.flags.f4Bit = 0;
  trafficTlv->flags.flags.f3Bit = 0;
  trafficTlv->flags.flags.f2Bit = 0;
  trafficTlv->flags.flags.f1Bit = 0;
  trafficTlv->freq = freq;
  trafficTlv->res = res;
  trafficTlv->weight = weight;
  trafficTlv->pdr.pdr = pdr;
  trafficTlv->pbs.pbs = pbs;
  trafficTlv->cdr.cdr = cdr;
  trafficTlv->cbs.cbs = cbs;
  trafficTlv->ebs.ebs = ebs;
  return MPLS_TLVFIXLEN;
}

int setupLblMsgIdTlv(mplsLdpLblMsgIdTlv_t * lblMsgIdTlv, unsigned int msgId)
{
  lblMsgIdTlv->baseTlv.flags.flags.tBit = MPLS_REQMSGID_TLVTYPE;
  lblMsgIdTlv->baseTlv.flags.flags.uBit = 0;
  lblMsgIdTlv->baseTlv.flags.flags.fBit = 0;
  lblMsgIdTlv->baseTlv.length = MPLS_MSGIDFIXLEN;
  lblMsgIdTlv->msgId = msgId;
  return MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN;
}
