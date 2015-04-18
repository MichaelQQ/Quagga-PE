
/******************************************************************************
*                       Nortel Networks Software License                      *
*                                                                             *
* READ THE TERMS OF THIS LICENSE CAREFULLY.  BY USING, MODIFYING, OR          *
* DISTRIBUTING THIS SOFTWARE AND ANY ACCOMPANYING DOCUMENTATION (COLLECTIVELY,*
* "SOFTWARE") YOU ARE AGREEING TO ALL OF THE TERMS OF THIS LICENSE.           *
*                                                                             *
* 1.      Nortel Telecom Limited, on behalf of itself and its subsidiaries    *
* (collectively "Nortel Networks") grants to you a non-exclusive, perpetual,  *
* world-wide right to use, copy, modify, and distribute the Software at no    *
* charge.                                                                     *
*                                                                             *
* 2.      You may sublicense recipients of redistributed Software to use,     *
* copy, modify, and distribute the Software on substantially the same terms as*
* this License.  You may not impose any further restrictions on the           *
* recipient's exercise of the rights in the Software granted under this       *
* License.  Software distributed to other parties must be accompanied by a    *
* License containing a grant, disclaimer and limitation of liability          *
* substantially in the form of 3, 4, and 5 below provided that references to  *
* "Nortel Networks" may be changed to "Supplier".                             *
*                                                                             *
* 3.      Nortel Networks reserves the right to modify and release new        *
* versions of the Software from time to time which may include modifications  *
* made by third parties like you. Accordingly, you agree that you shall       *
* automatically grant a license to Nortel Networks to include, at its option, *
* in any new version of the Software any modifications to the Software made by*
* you and made available directly or indirectly to Nortel Networks.  Nortel   *
* Networks shall have the right to use, copy, modify, and distribute any such *
* modified Software on substantially the same terms as this License.          *
*                                                                             *
* 4.      THE SOFTWARE IS PROVIDED ON AN "AS IS" BASIS.  NORTEL NETWORKS AND  *
* ITS AGENTS AND SUPPLIERS DISCLAIM ALL REPRESENTATIONS, WARRANTIES AND       *
* CONDITIONS RELATING TO THE SOFTWARE, INCLUDING, BUT NOT LIMITED TO, IMPLIED *
* WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND         *
* NON-INFRINGEMENT OF THIRD-PARTY INTELLECTUAL PROPERTY RIGHTS.  NORTEL       *
* NETWORKS AND ITS AGENTS AND SUPPLIERS DO NOT WARRANT, GUARANTEE, OR MAKE ANY*
* REPRESENTATIONS REGARDING THE USE, OR THE RESULTS OF THE USE, OF THE        *
* SOFTWARE IN TERMS OR CORRECTNESS, ACCURACY, RELIABILITY, CURRENTNESS, OR    *
* OTHERWISE.                                                                  *
*                                                                             *
* 5.      NEITHER NORTEL NETWORKS NOR ANY OF ITS AGENTS OR SUPPLIERS SHALL BE *
* LIABLE FOR ANY DIRECT, INDIRECT, CONSEQUENTIAL, INCIDENTAL OR EXEMPLARY     *
* DAMAGES, OR ECONOMIC LOSSES (INCLUDING DAMAGES FOR LOSS OF BUSINESS PROFITS,*
* BUSINESS INTERRUPTION, LOSS OF BUSINESS INFORMATION AND THE LIKE), ARISING  *
* FROM THE SOFTWARE OR THIS LICENSE AGREEMENT, EVEN IF NORTEL NETWORKS OR SUCH*
* AGENT OR SUPPLIER HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES OR    *
* LOSSES, AND WHETHER ANY SUCH DAMAGE OR LOSS ARISES OUT OF CONTRACT, TORT, OR*
* OTHERWISE.                                                                  *
*                                                                             *
* 6.      This License shall be governed by the laws of the Province of       *
* Ontario, Canada.                                                            *
*******************************************************************************/

/******************************************************************************
 * This file contains the C implementation for encode/decode functions        * 
 * for the following types of messages: notification, hello, initialization,  *
 * keepAlive, address, address Withdraw, label Mapping, label Request, label  *
 * Withdraw and label Release. There are also encode/decode methods for all   * 
 * tlv types required by the previously enumerated messages.                  * 
 * Please remember that the pdu will always contain the header followed by 1  *
 * or more LDP messages. The file contains functions to encode/decode the LDP *
 * header as well.  							      * 
 * All the messages, header message and the tlvs are in conformity with the   * 
 * draft-ietf-mpls-ldp-04  (May 1999) and with draft-ietf-mpls-cr-ldp-01      *
 * (Jan 1999). 								      * 
 *								              *
 * Please note that the U bit in the message and the F bit in the tlv are     *
 * ignored in this version of the code.                                       *
 *								              *
 * Please note that the traffic parameters for traffic TLV have to be IEEE    *
 * single precision floating point numbers.                                   *
 *								              *
 * Please note that there might be a small chance for bit field manipulation  *
 * portability inconsistency. If such problems occure, the code requires      *
 * changes for a suitable bit-field manipulation. The code for encoding and   *
 * decoding makes the assumption that the compiler packs the bit fields in a  *
 * structure into adjacent bits of the same unit.                             * 
 *								              *
 * The usage of the encode/decode functions is described below.               * 
 *								              *
 * The encode functions take as arguments: a pointer to the structure which   *
 * implements msg/tlv, a buffer (where the encoding is done) and the buffer   *
 * length.							              *
 * If the encode is successfull, the function returns the total encoded       * 
 * length.								      *
 * If the encode fails, the function returns an error code.                   *
 * The encode functions for messages and message headers do not modify the    *
 * content of the struct which is to be encoded. All the other encode         *
 * functions will change the content of the structure. The pointer which      *
 * points to the beginning of the buffer is not changed.                      *
 *									      *
 * The decode functions take as arguments: a pointer to the structure which   *
 * is going to be populated after decoding, a pointer to a buffer and the     *
 * buffer length.							      *
 * If the decode is successful, the function returns the total decoded length *
 * If the decode fails, the function returns an error code. The decode        *
 * functions do not modify the pointer to the buffer which contains the data  *
 * to be decoded.							      *
 *									      *
 * Example on how to use the encode/decode functions for a keepAlive message: *
 *									      *
 *           Encode the keep alive message:                                   * 
 *           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^    				      *
 *           u_char buffer[500];	 				      *
 *           int returnCode; 						      *
 *           struct mplsLdpKeepAlMsg_s keepAliveMsg;            	      *
 *           keepAliveMsg.baseMsg.msgType   = MPLS_KEEPAL_MSGTYPE;            *
 *           keepAliveMsg.baseMsg.msgLength = MPLS_MSGIDFIXLEN;               *
 *           keepAliveMsg.baseMsg.msgId     = 123;		              *
 *           memset(buffer, 0, 500);                                  	      *
 *           returnCode = Mpls_encodeLdpKeepAliveMsg(&keepAliveMsg,           *
 *                                                   buffer,                  *
 *                                                   500);                    *
 *           if (returnCode < 0)                                              *
 *              check the error code				              *
 *           else                                                             *
 *              write(fd, buffer, returnCode);                                *
 *									      *
 *									      *
 *           Decode the keep alive meesage:                                   *
 *           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^		                      *
 *           u_char buffer[500];					      *
 *           int returnCode;					              *
 *           struct mplsLdpKeepAlMsg_s keepAliveMsg;	            	      *
 *           read(fd, buffer, length);                                        *
 *           returnCode =  Mpls_decodeLdpKeepAliveMsg(&keepAliveMsg,          * 
 *                                                    buffer,                 *
 *                                                    500); 		      *
 *           if (returnCode < 0)	                                      *
 *              check the error code					      *
 *           else				 			      *
 *           { 								      *
 *              printKeepAliveMsg(&keepAliveMsg);	 	              *
 *           } 						                      *
 *								              *
 * An example on how to use the decode functions for the header and the       *
 * messages can be found in the main function.                                *
 *								              *
 * The code was tested for big endian and little endian for sparc5, linux     *
 * and i960.                                                                  *
 *								              *
 * In order to compile for little endian, the LITTLE_ENDIAN_BYTE_ORDER should *
 * be defined.								      *
 *								              *
 * At the end of this file there is an examples of a hex buffers and its      *
 * corresponding values.                                                      *
 *								              *
 *								              *
 * Version History                                                            *
 * Version          Date      Authors            Description                  *
 * ===========      ========  =========          ======================       *
 * mpls_encdec_01.c 99/03/15  Antonela Paraschiv draft-ietf-mpls-ldp-03 and   * 
 *                                               draft-ietf-mpls-cr-ldp-01    *
 *								              *
 * mpls_encdec_02.c 99/05/19  Antonela Paraschiv draft-ietf-mpls-ldp-04 and   * 
 *                                               draft-ietf-mpls-cr-ldp-01    *
 *								              *
 ******************************************************************************/

#ifdef VXWORKS
#include <in.h>                 /* htons, htonl, ntohs, ntohl         */
#include <types.h>              /* u_int, u_char, u_short, float etc. */
#else
#include <netinet/in.h>         /* htons, htonl, ntohs, ntohl         */
#include <sys/types.h>          /* u_int, u_char, u_short, float etc. */
#endif /* VXWORKS */

#include "ldp_struct.h"
#include "mpls_trace_impl.h"
#include "ldp_nortel.h"

int global_ldp_pdu_debug = 0;

/*
 *      Encode-decode for Ldp Msg Header 
 */

/* 
 * Encode:
 */
int Mpls_encodeLdpMsgHeader
  (mplsLdpHeader_t * header, u_char * buff, int bufSize) {
  mplsLdpHeader_t headerCopy;

  if (MPLS_LDP_HDRSIZE > bufSize) {
    /* not enough room for header */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  headerCopy = *header;
  headerCopy.protocolVersion = htons(headerCopy.protocolVersion);
  headerCopy.pduLength = htons(headerCopy.pduLength);
  headerCopy.lsrAddress = htonl(headerCopy.lsrAddress);
  headerCopy.labelSpace = htons(headerCopy.labelSpace);

  MEM_COPY(buff, (u_char *) & headerCopy, MPLS_LDP_HDRSIZE);

  return MPLS_LDP_HDRSIZE;

}                               /* End : Mpls_encodeLdpMsgHeader */

/* 
 * Decode: 
 */
int Mpls_decodeLdpMsgHeader
  (mplsLdpHeader_t * header, u_char * buff, int bufSize) {
  if (MPLS_LDP_HDRSIZE > bufSize) {
    return MPLS_DEC_BUFFTOOSMALL;
  }

  MEM_COPY((u_char *) header, buff, MPLS_LDP_HDRSIZE);

  header->protocolVersion = ntohs(header->protocolVersion);
  header->pduLength = ntohs(header->pduLength);
  header->lsrAddress = ntohl(header->lsrAddress);
  header->labelSpace = ntohs(header->labelSpace);

  /* check if the length is over the max length */
  if (header->pduLength > MPLS_PDUMAXLEN) {
    return MPLS_PDU_LENGTH_ERROR;
  }

  return MPLS_LDP_HDRSIZE;

}                               /* End: Mpls_decodeLdpMsgHeader */

/*
 *      Encode-decode for Ldp Base Message
 */

/* 
 * Encode:
 */
int Mpls_encodeLdpBaseMsg(mplsLdpMsg_t * ldpMsg, u_char * buff, int bufSize)
{
  if (MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN > bufSize) {
    /* not enough room for header */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  ldpMsg->flags.mark = htons(ldpMsg->flags.mark);
  ldpMsg->msgLength = htons(ldpMsg->msgLength);
  ldpMsg->msgId = htonl(ldpMsg->msgId);

  MEM_COPY(buff, (u_char *) ldpMsg, MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN);

  return (MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN);

}                               /* End : Mpls_encodeLdpBaseMsg */

/* 
 * Decode: 
 */
int Mpls_decodeLdpBaseMsg(mplsLdpMsg_t * ldpMsg, u_char * buff, int bufSize)
{
  if (MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN > bufSize) {
    return MPLS_DEC_BUFFTOOSMALL;
  }

  MEM_COPY((u_char *) ldpMsg, buff, MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN);

  ldpMsg->flags.mark = ntohs(ldpMsg->flags.mark);
  ldpMsg->msgLength = ntohs(ldpMsg->msgLength);
  ldpMsg->msgId = ntohl(ldpMsg->msgId);

  return MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN;

}                               /* End: Mpls_decodeLdpBaseMsg */

/*
 *      Encode-decode for ATM Label Range Component
 */

/* 
 * encode: 
 */
int Mpls_encodeLdpAtmLblRng
  (mplsLdpAtmLblRng_t * atmLbl, u_char * buff, int bufSize) {
  if (MPLS_ATMLRGFIXLEN > bufSize) {
    /* not enough room for label */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  atmLbl->flags.flags.res1 = 0;
  atmLbl->flags.flags.res2 = 0;
  atmLbl->flags.mark[0] = htonl(atmLbl->flags.mark[0]);
  atmLbl->flags.mark[1] = htonl(atmLbl->flags.mark[1]);

  MEM_COPY(buff, (u_char *) atmLbl, MPLS_ATMLRGFIXLEN);

  return MPLS_ATMLRGFIXLEN;

}                               /* End Mpls_encodeLdpAtmLblRng */

/* 
 * decode: 
 */
int Mpls_decodeLdpAtmLblRng
  (mplsLdpAtmLblRng_t * atmLbl, u_char * buff, int bufSize) {
  if (MPLS_ATMLRGFIXLEN > bufSize) {
    PRINT_ERR("failed decoding the Atm Lbl Rng\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  MEM_COPY((u_char *) atmLbl, buff, MPLS_ATMLRGFIXLEN);

  atmLbl->flags.mark[0] = ntohl(atmLbl->flags.mark[0]);
  atmLbl->flags.mark[1] = ntohl(atmLbl->flags.mark[1]);

  return MPLS_ATMLRGFIXLEN;

}                               /* End Mpls_decodeLdpAtmLblRng */

/*
 *      Encode-decode for ATM Session Parameters 
 */

/* 
 * encode: 
 */
int Mpls_encodeLdpAsp(mplsLdpAspTlv_t * atmAsp, u_char * buff, int bufSize)
{
  int encodedSize = 0;
  u_short totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_int i, numLblRng;

  /* get the size of the atmAsp to be encoded and check it against
     the buffer size */

  if (MPLS_TLVFIXLEN + (int)(atmAsp->baseTlv.length) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(atmAsp->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;
  totalSize += encodedSize;

  /* 
   *  encode for M + N + D + res 
   */
  numLblRng = atmAsp->flags.flags.numLblRng;
  atmAsp->flags.flags.res = 0;
  atmAsp->flags.mark = htonl(atmAsp->flags.mark);

  MEM_COPY(tempBuf, (u_char *) & (atmAsp->flags.mark), MPLS_ASPFIXLEN);
  tempBuf += MPLS_ASPFIXLEN;
  totalSize += MPLS_ASPFIXLEN;

  /* 
   *  encode for ATM labels 
   */
  for (i = 0; i < numLblRng; i++) {
    encodedSize = Mpls_encodeLdpAtmLblRng(&(atmAsp->lblRngList[i]),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_ATMLBLERROR;
    }
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End Mpls_encodeLdpAsp */

/* 
 * decode: 
 */
int Mpls_decodeLdpAsp(mplsLdpAspTlv_t * atmAsp, u_char * buff, int bufSize)
{
  int decodedSize = 0;
  u_short totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_int i;

  if (MPLS_ASPFIXLEN > bufSize) {
    /* the buffer does not contain even the required field */
    PRINT_ERR("failed in decoding LdpAsp\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /* 
   *  decode for M + N + D + res 
   */
  MEM_COPY((u_char *) & (atmAsp->flags.mark), tempBuf, MPLS_ASPFIXLEN);
  tempBuf += MPLS_ASPFIXLEN;
  totalSize += MPLS_ASPFIXLEN;

  atmAsp->flags.mark = ntohl(atmAsp->flags.mark);

  /*
   *  decode for ATM labels 
   */
  for (i = 0; i < atmAsp->flags.flags.numLblRng; i++) {
    decodedSize = Mpls_decodeLdpAtmLblRng(&(atmAsp->lblRngList[i]),
      tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      PRINT_ERR("failed in decoding LdpAtmLabel[%d] for LdpAsp\n", i);
      return MPLS_DEC_ATMLBLERROR;
    }
    tempBuf += decodedSize;
    totalSize += decodedSize;
  }

  return totalSize;

}                               /* End Mpls_decodeLdpAsp */

/*
 *      Encode-decode for TLV
 */

/* 
 * encode: 
 */
int Mpls_encodeLdpTlv(mplsLdpTlv_t * tlv, u_char * buff, int bufSize)
{
  if (MPLS_TLVFIXLEN > bufSize) {
    /* not enough room for label */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  tlv->flags.mark = htons(tlv->flags.mark);
  tlv->length = htons(tlv->length);

  MEM_COPY(buff, (u_char *) tlv, MPLS_TLVFIXLEN);

  return MPLS_TLVFIXLEN;

}                               /* End: Mpls_encodeLdpTlv */

/* 
 * decode: 
 */
int Mpls_decodeLdpTlv(mplsLdpTlv_t * tlv, u_char * buff, int bufSize)
{
  if (MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("Failed decoding TLV\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  MEM_COPY((u_char *) tlv, buff, MPLS_TLVFIXLEN);

  tlv->flags.mark = ntohs(tlv->flags.mark);
  tlv->length = ntohs(tlv->length);

  return MPLS_TLVFIXLEN;

}                               /* End: Mpls_decodeLdpTlv */

/*
 *      Encode-decode for CSP (common session param)
 */

/* 
 * encode: 
 */
int Mpls_encodeLdpCsp(mplsLdpCspTlv_t * csp, u_char * buff, int bufSize)
{
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_char *cspPtr;

  if (MPLS_CSPFIXLEN + MPLS_TLVFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  cspPtr = (u_char *) csp;

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(csp->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in CSP\n");
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;
  cspPtr += encodedSize;

  /* 
   *  encode for the rest of the Csp 
   */
  csp->protocolVersion = htons(csp->protocolVersion);
  csp->holdTime = htons(csp->holdTime);
  csp->flags.mark = htons(csp->flags.mark);
  csp->maxPduLen = htons(csp->maxPduLen);
  csp->rcvLsrAddress = htonl(csp->rcvLsrAddress);
  csp->rcvLsId = htons(csp->rcvLsId);

  MEM_COPY(tempBuf, cspPtr, MPLS_CSPFIXLEN);

  return (MPLS_CSPFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpCsp */

/* 
 * decode: 
 */
int Mpls_decodeLdpCsp(mplsLdpCspTlv_t * csp, u_char * buff, int bufSize)
{
  u_char *cspPtr;

  if (MPLS_CSPFIXLEN > bufSize) {
    /* not enough data for Csp */
    PRINT_ERR("failed decoding LdpCsp\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  cspPtr = (u_char *) csp;
  cspPtr += MPLS_TLVFIXLEN;     /* we want to point to the flags since the
                                   tlv was decoded before we reach here */

  /* 
   *  decode for the rest of the Csp 
   */
  MEM_COPY(cspPtr, buff, MPLS_CSPFIXLEN);

  csp->protocolVersion = ntohs(csp->protocolVersion);
  csp->holdTime = ntohs(csp->holdTime);
  csp->flags.mark = ntohs(csp->flags.mark);
  csp->maxPduLen = ntohs(csp->maxPduLen);
  csp->rcvLsrAddress = ntohl(csp->rcvLsrAddress);
  csp->rcvLsId = ntohs(csp->rcvLsId);

  return MPLS_CSPFIXLEN;

}                               /* Mpls_decodeLdpCsp */

/*
 *      Encode-decode for Fr Session Parameters
 */

/* 
 * encode
 */
int Mpls_encodeLdpFsp(mplsLdpFspTlv_t * frFsp, u_char * buff, int bufSize)
{
  int encodedSize = 0;
  u_short totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_int i, numLblRng;

  /* get the size of the frAsp to be encoded and check it against
     the buffer size */

  if (MPLS_TLVFIXLEN + (int)(frFsp->baseTlv.length) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(frFsp->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;
  totalSize += encodedSize;

  /* 
   *  encode for M + N + dir + res 
   */
  numLblRng = frFsp->flags.flags.numLblRng;
  frFsp->flags.flags.res = 0;
  frFsp->flags.mark = htonl(frFsp->flags.mark);

  MEM_COPY(tempBuf, (u_char *) & (frFsp->flags.mark), MPLS_FSPFIXLEN);
  tempBuf += MPLS_FSPFIXLEN;
  totalSize += MPLS_FSPFIXLEN;

  /* 
   *  encode for FR labels 
   */
  for (i = 0; i < numLblRng; i++) {
    encodedSize = Mpls_encodeLdpFrLblRng(&(frFsp->lblRngList[i]),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_FSPLBLERROR;
    }
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End: Mpls_encodeLdpFsp */

/* 
 * decode
 */
int Mpls_decodeLdpFsp(mplsLdpFspTlv_t * frFsp, u_char * buff, int bufSize)
{
  int decodedSize = 0;
  u_short totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_int i;

  if (MPLS_FSPFIXLEN > bufSize) {
    /* the buffer does not contain even the required field */
    PRINT_ERR("failed in decoding LdpFsp\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /* 
   *  decode for M + N + res 
   */
  MEM_COPY((u_char *) & (frFsp->flags.mark), tempBuf, MPLS_FSPFIXLEN);
  tempBuf += MPLS_FSPFIXLEN;
  totalSize += MPLS_FSPFIXLEN;

  frFsp->flags.mark = ntohl(frFsp->flags.mark);

  /*
   *  decode for FR labels 
   */
  for (i = 0; i < frFsp->flags.flags.numLblRng; i++) {
    decodedSize = Mpls_decodeLdpFrLblRng(&(frFsp->lblRngList[i]),
      tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      PRINT_ERR("failed in decoding LdpFrLabel[%d] for LdpFsp\n", i);
      return MPLS_DEC_FSPLBLERROR;
    }
    tempBuf += decodedSize;
    totalSize += decodedSize;
  }

  return totalSize;

}                               /* End: Mpls_decodeLdpFsp */

/*
 *      Encode-decode for INIT msg 
 */

/* 
 * encode for init message 
 */
int Mpls_encodeLdpInitMsg
  (mplsLdpInitMsg_t * initMsg, u_char * buff, int bufSize) {
  mplsLdpInitMsg_t initMsgCopy;
  int encodedSize, totalSize;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  initMsgCopy = *initMsg;
  totalSize = 0;

  /* check the length of the messageId + mandatory param +
     optional param */
  if ((int)(initMsgCopy.baseMsg.msgLength) + MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("failed to encode the init msg: BUFFER TOO SMALL\n");
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /*
   *  encode the base part of the pdu message
   */
  encodedSize = Mpls_encodeLdpBaseMsg(&(initMsgCopy.baseMsg), tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_BASEMSGERROR;
  }
  PRINT_OUT("Encode BaseMsg for init on %d bytes\n", encodedSize);
  tempBuf += encodedSize;
  totalSize += encodedSize;

  /*
   *  encode the csp if any 
   */
  if (initMsgCopy.cspExists) {
    encodedSize = Mpls_encodeLdpCsp(&(initMsgCopy.csp),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_CSPERROR;
    }
    PRINT_OUT("Encoded for CSP %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  /*
   *  encode the asp if any 
   */
  if (initMsgCopy.aspExists) {

    encodedSize = Mpls_encodeLdpAsp(&(initMsgCopy.asp),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_ASPERROR;
    }
    PRINT_OUT("Encoded for ASP %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  /*
   *  encode the fsp if any 
   */
  if (initMsgCopy.fspExists) {
    encodedSize = Mpls_encodeLdpFsp(&(initMsgCopy.fsp),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_FSPERROR;
    }
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End: Mpls_encodeLdpInitMsg */

/* 
 * decode for unknown message 
 */
int Mpls_decodeLdpUnknownMsg
  (mplsLdpUnknownMsg_t * msg, u_char * buff, int bufSize) {
  int decodedSize = 0;
  u_int totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  /*
   *  decode the base part of the pdu message
   */
  memset(msg, 0, sizeof(mplsLdpMsg_t));
  decodedSize = Mpls_decodeLdpBaseMsg(&(msg->baseMsg), tempBuf, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for unknown on %d bytes\n", decodedSize);

  tempBuf += decodedSize;
  totalSize += decodedSize;

  if (bufSize - totalSize <= 0) {
    /* nothing left for decoding */
    PRINT_ERR("Init msg does not have anything beside base msg\n");
    return totalSize;
  }

  if (msg->baseMsg.msgLength > MPLS_NOT_MAXSIZE) {
    PRINT_ERR("Message is too big for unknow message buffer.\n");
    return MPLS_DEC_BASEMSGERROR;
  }

  memcpy(msg->data, tempBuf, msg->baseMsg.msgLength);
  decodedSize = msg->baseMsg.msgLength;

  tempBuf += decodedSize;
  totalSize += decodedSize;

  PRINT_OUT("totalsize for Mpls_decodeLdpUnknowntMsg is %d\n", totalSize);

  return totalSize;
}

/* 
 * decode for init message 
 */
int Mpls_decodeLdpInitMsg
  (mplsLdpInitMsg_t * initMsg, u_char * buff, int bufSize) {
  int decodedSize = 0;
  u_int totalSize = 0;
  u_int stopLength = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_int totalSizeParam = 0;
  mplsLdpTlv_t tlvTemp;

  /*
   *  decode the base part of the pdu message
   */
  memset(initMsg, 0, sizeof(mplsLdpInitMsg_t));
  decodedSize = Mpls_decodeLdpBaseMsg(&(initMsg->baseMsg), tempBuf, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for init on %d bytes\n", decodedSize);

  if (initMsg->baseMsg.flags.flags.msgType != MPLS_INIT_MSGTYPE) {
    PRINT_ERR("Not the right message type; expected init and got %x\n",
      initMsg->baseMsg.flags.flags.msgType);
    return MPLS_MSGTYPEERROR;
  }
  tempBuf += decodedSize;
  totalSize += decodedSize;

  if (bufSize - totalSize <= 0) {
    /* nothing left for decoding */
    PRINT_ERR("Init msg does not have anything beside base msg\n");
    return totalSize;
  }

  PRINT_OUT("bufSize = %d,  totalSize = %d, initMsg->baseMsg.msgLength = %d\n",
    bufSize, totalSize, initMsg->baseMsg.msgLength);

  /* Have to check the baseMsg.msgLength to know when to finish.
   * We finsh when the totalSizeParam is >= to the base message length - the
   * message id length (4) 
   */

  stopLength = initMsg->baseMsg.msgLength - MPLS_MSGIDFIXLEN;
  while (stopLength > totalSizeParam) {
    /*
     *  decode the tlv to check what's next
     */
    decodedSize = Mpls_decodeLdpTlv(&tlvTemp, tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      /* something wrong */
      PRINT_ERR("INIT msg decode failed for tlv\n");
      return MPLS_DEC_TLVERROR;
    }

    tempBuf += decodedSize;
    totalSize += decodedSize;
    totalSizeParam += decodedSize;

    switch (tlvTemp.flags.flags.tBit) {
      case MPLS_CSP_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpCsp(&(initMsg->csp),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding Csp from init msg\n");
            return MPLS_DEC_CSPERROR;
          }
          PRINT_OUT("Decoded for CSP %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;
          initMsg->cspExists = 1;
          initMsg->csp.baseTlv = tlvTemp;
          break;
        }
      case MPLS_ASP_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpAsp(&(initMsg->asp),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding Asp from init msg\n");
            return MPLS_DEC_ASPERROR;
          }
          PRINT_OUT("Decoded for ASP %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;
          initMsg->aspExists = 1;
          initMsg->asp.baseTlv = tlvTemp;
          break;
        }
      case MPLS_FSP_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpFsp(&(initMsg->fsp),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding Fsp from init msg\n");
            return MPLS_DEC_FSPERROR;
          }
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;
          initMsg->fspExists = 1;
          initMsg->fsp.baseTlv = tlvTemp;
          break;
        }
      default:
        {
          PRINT_ERR("Found wrong tlv type while decoding init msg (%d)\n",
            tlvTemp.flags.flags.tBit);
          if (tlvTemp.flags.flags.uBit == 1) {
            /* ignore the Tlv and continue processing */
            tempBuf += tlvTemp.length;
            totalSize += tlvTemp.length;
            totalSizeParam += tlvTemp.length;
            break;
          } else {
            /* drop the message; return error */
            return MPLS_TLVTYPEERROR;
          }
        }
    }                           /* switch type */

  }                             /* while */

  PRINT_OUT("totalsize for Mpls_decodeLdpInitMsg is %d\n", totalSize);

  return totalSize;

}                               /* End: Mpls_decodeLdpInitMsg */

/*
 *      Encode-decode for Fr Label Range 
 */

/* 
 * encode
 */
int Mpls_encodeLdpFrLblRng
  (mplsLdpFrLblRng_t * frLabel, u_char * buff, int bufSize) {
  if (MPLS_FRLRGFIXLEN > bufSize) {
    /* not enough room for label */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  frLabel->flags.flags.res_min = 0;
  frLabel->flags.flags.res_max = 0;
  frLabel->flags.mark[0] = htonl(frLabel->flags.mark[0]);
  frLabel->flags.mark[1] = htonl(frLabel->flags.mark[1]);

  MEM_COPY(buff, (u_char *) frLabel, MPLS_FRLRGFIXLEN);

  return MPLS_FRLRGFIXLEN;

}                               /* End: Mpls_encodeLdpFrLblRng */

/* 
 * decode
 */
int Mpls_decodeLdpFrLblRng
  (mplsLdpFrLblRng_t * frLabel, u_char * buff, int bufSize) {
  if (MPLS_FRLRGFIXLEN > bufSize) {
    PRINT_ERR("failed decoding the Fr Lbl Rng\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  MEM_COPY((u_char *) frLabel, buff, MPLS_FRLRGFIXLEN);

  frLabel->flags.mark[0] = ntohl(frLabel->flags.mark[0]);
  frLabel->flags.mark[1] = ntohl(frLabel->flags.mark[1]);

  return MPLS_FRLRGFIXLEN;

}                               /* End: Mpls_decodeLdpFrLblRng */

/*
 *      Encode-decode for NOTIFICATION msg 
 */

/* 
 * encode for notification message 
 */
int Mpls_encodeLdpNotMsg(mplsLdpNotifMsg_t * notMsg, u_char * buff, int bufSize)
{
  mplsLdpNotifMsg_t notMsgCopy;
  int encodedSize = 0;
  u_int totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  /* check the length of the messageId + mandatory param +
     optional param */
  if ((int)(notMsg->baseMsg.msgLength) + MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("failed to encode the not msg: BUFFER TOO SMALL\n");
    return MPLS_ENC_BUFFTOOSMALL;
  }

  notMsgCopy = *notMsg;

  /*
   *  encode the base part of the pdu message
   */
  encodedSize = Mpls_encodeLdpBaseMsg(&(notMsgCopy.baseMsg), tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_BASEMSGERROR;
  }
  PRINT_OUT("Encode BaseMsg for not on %d bytes\n", encodedSize);

  tempBuf += encodedSize;
  totalSize += encodedSize;

  if (notMsgCopy.statusTlvExists) {
    encodedSize = Mpls_encodeLdpStatus(&(notMsgCopy.status),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_STATUSERROR;
    }
    PRINT_OUT("Encoded for STATUS %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (notMsgCopy.exStatusTlvExists) {
    encodedSize = Mpls_encodeLdpExStatus(&(notMsgCopy.exStatus),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_EXSTATERROR;
    }
    PRINT_OUT("Encoded for EXTENDED STATUS %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (notMsgCopy.retPduTlvExists) {
    encodedSize = Mpls_encodeLdpRetPdu(&(notMsgCopy.retPdu),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_RETPDUERROR;
    }
    PRINT_OUT("Encoded for RET PDU %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (notMsgCopy.retMsgTlvExists) {
    encodedSize = Mpls_encodeLdpRetMsg(&(notMsgCopy.retMsg),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_RETMSGERROR;
    }
    PRINT_OUT("Encoded for RET MSG %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (notMsgCopy.lspidTlvExists) {
    encodedSize = Mpls_encodeLdpLspIdTlv(&(notMsgCopy.lspidTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_LSPIDERROR;
    }
    PRINT_OUT("Encoded for LSPID Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End: Mpls_encodeLdpNotMsg */

/* 
 * decode for notification message 
 */
int Mpls_decodeLdpNotMsg(mplsLdpNotifMsg_t * notMsg, u_char * buff, int bufSize)
{
  int decodedSize = 0;
  u_int totalSize = 0;
  u_int stopLength = 0;
  u_int totalSizeParam = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  mplsLdpTlv_t tlvTemp;

  /*
   *  decode the base part of the pdu message
   */
  memset(notMsg, 0, sizeof(mplsLdpNotifMsg_t));
  decodedSize = Mpls_decodeLdpBaseMsg(&(notMsg->baseMsg), tempBuf, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for not on %d bytes\n", decodedSize);

  if (notMsg->baseMsg.flags.flags.msgType != MPLS_NOT_MSGTYPE) {
    PRINT_ERR("Not the right message type; expected not and got %x\n",
      notMsg->baseMsg.flags.flags.msgType);
    return MPLS_MSGTYPEERROR;
  }

  tempBuf += decodedSize;
  totalSize += decodedSize;

  if (bufSize - totalSize <= 0) {
    /* nothing left for decoding */
    PRINT_ERR("Not msg does not have anything beside base msg\n");
    return totalSize;
  }

  PRINT_OUT("bufSize = %d,  totalSize = %d, notMsg->baseMsg.msgLength = %d\n",
    bufSize, totalSize, notMsg->baseMsg.msgLength);

  /* Have to check the baseMsg.msgLength to know when to finish.
   * We finsh when the totalSizeParam is >= to the base message length - the
   * message id length (4) 
   */

  stopLength = notMsg->baseMsg.msgLength - MPLS_MSGIDFIXLEN;
  while (stopLength > totalSizeParam) {
    /*
     *  decode the tlv to check what's next
     */
    memset(&tlvTemp, 0, MPLS_TLVFIXLEN);
    decodedSize = Mpls_decodeLdpTlv(&tlvTemp, tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      /* something wrong */
      PRINT_ERR("NOT msg decode failed for tlv\n");
      return MPLS_DEC_TLVERROR;
    }

    tempBuf += decodedSize;
    totalSize += decodedSize;
    totalSizeParam += decodedSize;

    switch (tlvTemp.flags.flags.tBit) {
      case MPLS_NOT_ST_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpStatus(&(notMsg->status),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding Status from not msg\n");
            return MPLS_DEC_STATUSERROR;
          }
          PRINT_OUT("Decoded for STATUS %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          notMsg->statusTlvExists = 1;
          notMsg->status.baseTlv = tlvTemp;
          break;
        }
      case MPLS_NOT_ES_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpExStatus(&(notMsg->exStatus),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding Extended Status from not msg\n");
            return MPLS_DEC_EXSTATERROR;
          }
          PRINT_OUT("Decoded for EX_STATUS %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          notMsg->exStatusTlvExists = 1;
          notMsg->exStatus.baseTlv = tlvTemp;
          break;
        }
      case MPLS_NOT_RP_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpRetPdu(&(notMsg->retPdu),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding Returned PDU from not msg\n");
            return MPLS_DEC_RETPDUERROR;
          }
          PRINT_OUT("Decoded for RET_PDU %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          notMsg->retPduTlvExists = 1;
          notMsg->retPdu.baseTlv = tlvTemp;
          break;
        }
      case MPLS_NOT_RM_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpRetMsg(&(notMsg->retMsg),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding Returned MSG from not msg\n");
            return MPLS_DEC_RETMSGERROR;
          }
          PRINT_OUT("Decoded for RET_MSG %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          notMsg->retMsgTlvExists = 1;
          notMsg->retMsg.baseTlv = tlvTemp;
          break;
        }
      case MPLS_LSPID_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpLspIdTlv(&(notMsg->lspidTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec LSPID tlv from Not msg\n");
            return MPLS_DEC_LSPIDERROR;
          }
          PRINT_OUT("Decoded for lspid tlv %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          notMsg->lspidTlvExists = 1;
          notMsg->lspidTlv.baseTlv = tlvTemp;
          break;
        }
      default:
        {
          PRINT_ERR("Found wrong tlv type while decoding not msg (%d)\n",
            tlvTemp.flags.flags.tBit);
          if (tlvTemp.flags.flags.uBit == 1) {
            /* ignore the Tlv and continue processing */
            tempBuf += tlvTemp.length;
            totalSize += tlvTemp.length;
            totalSizeParam += tlvTemp.length;
            break;
          } else {
            /* drop the message; return error */
            return MPLS_TLVTYPEERROR;
          }
        }
    }                           /* switch type */

  }                             /* while */

  PRINT_OUT("totalsize for Mpls_decodeLdpNotMsg is %d\n", totalSize);

  return totalSize;

}                               /* End: Mpls_decodeLdpNotMsg */

/*
 *      Encode-decode for Status TLV 
 */

/* 
 * encode:
 */
int Mpls_encodeLdpStatus
  (mplsLdpStatusTlv_t * status, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_char *statusPtr;

  if (MPLS_STATUSFIXLEN + MPLS_TLVFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(status->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in STATUS\n");
    return MPLS_ENC_TLVERROR;
  }

  statusPtr = (u_char *) status;
  tempBuf += encodedSize;
  statusPtr += encodedSize;

  /* 
   *  encode for the rest of the  Status
   */
  status->flags.mark = htonl(status->flags.mark);
  status->msgId = htonl(status->msgId);
  status->msgType = htons(status->msgType);

  MEM_COPY(tempBuf, statusPtr, MPLS_STATUSFIXLEN);

  return (MPLS_STATUSFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpStatus */

/* 
 * decode:
 */
int Mpls_decodeLdpStatus
  (mplsLdpStatusTlv_t * status, u_char * buff, int bufSize) {
  u_char *statusPtr;

  if (MPLS_STATUSFIXLEN > bufSize) {
    /* not enough data for Status */
    PRINT_ERR("failed decoding Status\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  statusPtr = (u_char *) status;
  statusPtr += MPLS_TLVFIXLEN;  /* we want to point to the flags since the
                                   tlv was decoded before we reach here */

  /* 
   *  decode for the rest of the Status
   */
  MEM_COPY(statusPtr, buff, MPLS_STATUSFIXLEN);

  status->flags.mark = ntohl(status->flags.mark);
  status->msgId = ntohl(status->msgId);
  status->msgType = ntohs(status->msgType);

  return MPLS_STATUSFIXLEN;

}                               /* End: Mpls_decodeLdpStatus */

/*
 *      Encode-decode for Extended Status TLV 
 */

/* 
 * encode:
 */
int Mpls_encodeLdpExStatus
  (mplsLdpExStatusTlv_t * status, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_EXSTATUSLEN + MPLS_TLVFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(status->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in EX_STATUS\n");
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  status->value = htonl(status->value);

  MEM_COPY(tempBuf, (u_char *) & (status->value), sizeof(u_int));

  return (MPLS_EXSTATUSLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpExStatus */

/* 
 * decode:
 */
int Mpls_decodeLdpExStatus
  (mplsLdpExStatusTlv_t * status, u_char * buff, int bufSize) {
  if (MPLS_EXSTATUSLEN > bufSize) {
    /* not enough data for ExStatus */
    PRINT_ERR("failed decoding ExStatus\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /* 
   *  decode for the rest of the Status
   */
  MEM_COPY(&(status->value), buff, MPLS_EXSTATUSLEN);

  status->value = ntohl(status->value);

  return MPLS_EXSTATUSLEN;

}                               /* End: Mpls_decodeLdpExStatus */

/*
 *      Encode-decode for Return PDU TLV
 */

/* 
 * encode:
 */
int Mpls_encodeLdpRetPdu
  (mplsLdpRetPduTlv_t * retPdu, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_short tempLength;           /* to store the tlv length for

                                   later use */

  if (MPLS_TLVFIXLEN + (int)(retPdu->baseTlv.length) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  tempLength = retPdu->baseTlv.length;
  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(retPdu->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in RET_PDU\n");
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  /* 
   *  encode the data of the ret pdu
   */

  encodedSize = Mpls_encodeLdpMsgHeader(&(retPdu->headerTlv),
    tempBuf, bufSize - encodedSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the header Tlv in RET_PDU\n");
    return MPLS_ENC_HDRTLVERROR;
  }
  tempBuf += encodedSize;

  MEM_COPY(tempBuf, retPdu->data, tempLength);

  return (MPLS_TLVFIXLEN + tempLength);

}                               /* End: Mpls_encodeLdpRetPdu */

/* 
 * decode:
 */
int Mpls_decodeLdpRetPdu
  (mplsLdpRetPduTlv_t * retPdu, u_char * buff, int bufSize, u_short tlvLength) {
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  int decodedSize;

  if ((int)tlvLength > bufSize) {
    /* not enough data for ExStatus */
    PRINT_ERR("failed decoding Ret pdu\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /* 
   *  decode data for ret pdu
   */
  decodedSize = Mpls_decodeLdpMsgHeader(&(retPdu->headerTlv), tempBuf, bufSize);
  if (decodedSize < 0) {
    PRINT_ERR("failed decoding the header Tlv in RET_PDU\n");
    return MPLS_DEC_HDRTLVERROR;
  }
  tempBuf += decodedSize;

  MEM_COPY(retPdu->data, tempBuf, tlvLength);

  return tlvLength;

}                               /* End: Mpls_decodeLdpRetPdu */

/*
 *      Encode-decode for Return Msg TLV 
 */

/* 
 * encode:
 */
int Mpls_encodeLdpRetMsg
  (mplsLdpRetMsgTlv_t * retMsg, u_char * buff, int bufSize) {
  u_char *retMsgPtr;
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_short tempLength;           /* to store the tlv length for

                                   later use */

  if (MPLS_TLVFIXLEN + (int)(retMsg->baseTlv.length) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  tempLength = retMsg->baseTlv.length;
  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(retMsg->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in RET_MSG\n");
    return MPLS_ENC_TLVERROR;
  }

  retMsgPtr = (u_char *) retMsg;
  tempBuf += encodedSize;
  retMsgPtr += encodedSize;

  /* 
   *  encode the data of the ret pdu
   */

  retMsg->msgType = htons(retMsg->msgType);
  retMsg->msgLength = htons(retMsg->msgLength);

  MEM_COPY(tempBuf, retMsgPtr, tempLength);

  return (MPLS_TLVFIXLEN + tempLength);

}                               /* End: Mpls_encodeLdpRetMsg */

/* 
 * decode:
 */
int Mpls_decodeLdpRetMsg
  (mplsLdpRetMsgTlv_t * retMsg, u_char * buff, int bufSize, u_short tlvLength) {
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_char *retMsgPtr;

  if ((int)tlvLength > bufSize) {
    /* not enough data for ExStatus */
    PRINT_ERR("failed decoding Ret msg\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }
  retMsgPtr = (u_char *) retMsg;
  retMsgPtr += MPLS_TLVFIXLEN;

  /* 
   *  decode data for ret msg 
   */
  MEM_COPY(retMsgPtr, tempBuf, tlvLength);

  retMsg->msgType = ntohs(retMsg->msgType);
  retMsg->msgLength = ntohs(retMsg->msgLength);

  return tlvLength;

}                               /* End: Mpls_decodeLdpRetMsg */

/*
 *      Encode-decode for HELLO msg 
 */

/* 
 * encode for HELLO message 
 */
int Mpls_encodeLdpHelloMsg
  (mplsLdpHelloMsg_t * helloMsg, u_char * buff, int bufSize) {
  mplsLdpHelloMsg_t helloMsgCopy;
  int encodedSize = 0;
  u_int totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  /* check the length of the messageId + mandatory param +
     optional param */
  if ((int)(helloMsg->baseMsg.msgLength) + MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("failed to encode the hello msg: BUFFER TOO SMALL\n");
    return MPLS_ENC_BUFFTOOSMALL;
  }

  helloMsgCopy = *helloMsg;

  /*
   *  encode the base part of the pdu message
   */
  encodedSize = Mpls_encodeLdpBaseMsg(&(helloMsgCopy.baseMsg),
    tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_BASEMSGERROR;
  }
  PRINT_OUT("Encode BaseMsg for hello on %d bytes\n", encodedSize);
  tempBuf += encodedSize;
  totalSize += encodedSize;

  /*
   *  encode the status tlv if any 
   */
  if (helloMsgCopy.chpTlvExists) {
    encodedSize = Mpls_encodeLdpChp(&(helloMsgCopy.chp),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_CHPERROR;
    }
    PRINT_OUT("Encoded for CHP %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (helloMsgCopy.trAdrTlvExists) {
    encodedSize = Mpls_encodeLdpTrAdr(&(helloMsgCopy.trAdr),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_TRADRERROR;
    }
    PRINT_OUT("Encoded for TR ADDR %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (helloMsgCopy.csnTlvExists) {
    encodedSize = Mpls_encodeLdpCsn(&(helloMsgCopy.csn),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_CSNERROR;
    }
    PRINT_OUT("Encoded for CSN %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End: Mpls_encodeLdpHelloMsg */

/* 
 * decode for HELLO message 
 */
int Mpls_decodeLdpHelloMsg
  (mplsLdpHelloMsg_t * helloMsg, u_char * buff, int bufSize) {
  int decodedSize = 0;
  u_int totalSize = 0;
  u_int stopLength = 0;
  u_int totalSizeParam = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  mplsLdpTlv_t tlvTemp;

  /*
   *  decode the base part of the pdu message
   */
  memset(helloMsg, 0, sizeof(mplsLdpHelloMsg_t));
  decodedSize = Mpls_decodeLdpBaseMsg(&(helloMsg->baseMsg), tempBuf, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for hello on %d bytes\n", decodedSize);

  if (helloMsg->baseMsg.flags.flags.msgType != MPLS_HELLO_MSGTYPE) {
    PRINT_ERR("Not the right message type; expected hello and got %x\n",
      helloMsg->baseMsg.flags.flags.msgType);
    return MPLS_MSGTYPEERROR;
  }

  tempBuf += decodedSize;
  totalSize += decodedSize;

  if (bufSize - totalSize <= 0) {
    /* nothing left for decoding */
    PRINT_ERR("Hello msg does not have anything beside base msg\n");
    return totalSize;
  }

  PRINT_OUT("bufSize = %d,  totalSize = %d, helloMsg->baseMsg.msgLength = %d\n",
    bufSize, totalSize, helloMsg->baseMsg.msgLength);

  /* Have to check the baseMsg.msgLength to know when to finish.
   * We finsh when the totalSizeParam is >= to the base message length - the
   * message id length (4) 
   */

  stopLength = helloMsg->baseMsg.msgLength - MPLS_MSGIDFIXLEN;
  while (stopLength > totalSizeParam) {
    /*
     *  decode the tlv to check what's next
     */
    memset(&tlvTemp, 0, MPLS_TLVFIXLEN);
    decodedSize = Mpls_decodeLdpTlv(&tlvTemp, tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      /* something wrong */
      PRINT_ERR("NOT msg decode failed for tlv\n");
      return MPLS_DEC_TLVERROR;
    }

    tempBuf += decodedSize;
    totalSize += decodedSize;
    totalSizeParam += decodedSize;

    switch (tlvTemp.flags.flags.tBit) {
      case MPLS_CHP_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpChp(&(helloMsg->chp),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding Chp from hello msg\n");
            return MPLS_DEC_CHPERROR;
          }
          PRINT_OUT("Decoded for CHP %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          helloMsg->chpTlvExists = 1;
          helloMsg->chp.baseTlv = tlvTemp;
          break;
        }
      case MPLS_TRADR_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpTrAdr(&(helloMsg->trAdr),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding TrAdr from hello msg\n");
            return MPLS_DEC_TRADRERROR;
          }
          PRINT_OUT("Decoded for TrAdr %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          helloMsg->trAdrTlvExists = 1;
          helloMsg->trAdr.baseTlv = tlvTemp;
          break;
        }
      case MPLS_CSN_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpCsn(&(helloMsg->csn),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding Csn from hello msg\n");
            return MPLS_DEC_CSNERROR;
          }
          PRINT_OUT("Decoded for CSN %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          helloMsg->csnTlvExists = 1;
          helloMsg->csn.baseTlv = tlvTemp;
          break;
        }
      default:
        {
          PRINT_ERR("Found wrong tlv type while decoding hello msg (%d)\n",
            tlvTemp.flags.flags.tBit);
          if (tlvTemp.flags.flags.uBit == 1) {
            /* ignore the Tlv and continue processing */
            tempBuf += tlvTemp.length;
            totalSize += tlvTemp.length;
            totalSizeParam += tlvTemp.length;
            break;
          } else {
            /* drop the message; return error */
            return MPLS_TLVTYPEERROR;
          }
        }
    }                           /* switch type */

  }                             /* while */

  PRINT_OUT("totalsize for Mpls_decodeLdpHelloMsg is %d\n", totalSize);

  return totalSize;

}                               /* End: Mpls_decodeLdpHelloMsg */

/* 
 * Encode for Common Hello Parameters TLV
 */

/*
 *  encode
 */
int Mpls_encodeLdpChp(mplsLdpChpTlv_t * chp, u_char * buff, int bufSize)
{
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_char *chpPtr;

  /* get the size of the chp to be encoded and check it against
     the buffer size */

  if (MPLS_TLVFIXLEN + MPLS_CHPFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(chp->baseTlv), tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }

  chpPtr = (u_char *) chp;
  tempBuf += encodedSize;
  chpPtr += encodedSize;

  /* 
   *  encode for hold time + T +  R + res 
   */
  chp->flags.flags.res = 0;
  chp->flags.mark = htons(chp->flags.mark);
  chp->holdTime = htons(chp->holdTime);

  MEM_COPY(tempBuf, chpPtr, MPLS_CHPFIXLEN);

  return (MPLS_TLVFIXLEN + MPLS_CHPFIXLEN);

}                               /* End: Mpls_encodeLdpChp */

/* 
 * decode
 */
int Mpls_decodeLdpChp(mplsLdpChpTlv_t * chp, u_char * buff, int bufSize)
{
  u_char *chpPtr;

  if (MPLS_CHPFIXLEN > bufSize) {
    /* not enough data for Chp */
    PRINT_ERR("failed decoding hello Chp\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  chpPtr = (u_char *) chp;
  chpPtr += MPLS_TLVFIXLEN;     /* we want to point to the flags since the
                                   tlv was decoded before we reach here */

  /*
   *  decode for the rest of the Chp
   */
  MEM_COPY(chpPtr, buff, MPLS_CHPFIXLEN);

  chp->holdTime = ntohs(chp->holdTime);
  chp->flags.mark = ntohs(chp->flags.mark);

  return MPLS_CHPFIXLEN;

}                               /* End: Mpls_decodeLdpChp */

/* 
 * Encode for Configuration Sequence Number TLV
 */

/*
 *  encode
 */
int Mpls_encodeLdpCsn(mplsLdpCsnTlv_t * csn, u_char * buff, int bufSize)
{
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_CSNFIXLEN + MPLS_TLVFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /*
   *  encode for tlv
   */
  encodedSize = Mpls_encodeLdpTlv(&(csn->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in hello Csn\n");
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  csn->seqNumber = htonl(csn->seqNumber);

  MEM_COPY(tempBuf, (u_char *) & (csn->seqNumber), MPLS_CSNFIXLEN);

  return (MPLS_CSNFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpCsn */

/* 
 * decode
 */
int Mpls_decodeLdpCsn(mplsLdpCsnTlv_t * csn, u_char * buff, int bufSize)
{
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_CSNFIXLEN > bufSize) {
    /* not enough data for csn data */
    PRINT_ERR("failed decoding hello Csn\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /*
   *  decode for the rest of the Csn 
   */
  MEM_COPY(&(csn->seqNumber), tempBuf, MPLS_CSNFIXLEN);

  csn->seqNumber = ntohl(csn->seqNumber);

  return MPLS_CSNFIXLEN;

}                               /* End: Mpls_decodeLdpCsn */

/* 
 * Encode for Transport Address TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpTrAdr(mplsLdpTrAdrTlv_t * trAdr, u_char * buff, int bufSize)
{
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_TRADRFIXLEN + MPLS_TLVFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /*
   *  encode for tlv
   */
  encodedSize = Mpls_encodeLdpTlv(&(trAdr->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in hello TrAdr\n");
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  trAdr->address = htonl(trAdr->address);

  MEM_COPY(tempBuf, (u_char *) & (trAdr->address), MPLS_TRADRFIXLEN);

  return (MPLS_TRADRFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpTrAdr */

/* 
 * decode 
 */
int Mpls_decodeLdpTrAdr(mplsLdpTrAdrTlv_t * trAdr, u_char * buff, int bufSize)
{
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_TRADRFIXLEN > bufSize) {
    /* not enough data for csn data */
    PRINT_ERR("failed decoding hello TrAdr\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /*
   *  decode for the rest of the TrAdr 
   */
  MEM_COPY(&(trAdr->address), tempBuf, MPLS_TRADRFIXLEN);

  trAdr->address = ntohl(trAdr->address);

  return MPLS_TRADRFIXLEN;

}                               /* End: Mpls_decodeLdpTrAdr */

/* 
 * Encode for KeepAlive Message
 */

/*
 *  encode
 */
int Mpls_encodeLdpKeepAliveMsg
  (mplsLdpKeepAlMsg_t * keepAlive, u_char * buff, int bufSize) {
  mplsLdpKeepAlMsg_t keepAliveCopy;
  int encodedSize = 0;

  if (MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("failed to encode the keep alive msg: BUFFER TOO SMALL\n");
    return MPLS_ENC_BUFFTOOSMALL;
  }

  keepAliveCopy = *keepAlive;

  encodedSize = Mpls_encodeLdpBaseMsg(&(keepAliveCopy.baseMsg), buff, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_BASEMSGERROR;
  }
  PRINT_OUT("Encode BaseMsg for keep alive on %d bytes\n", encodedSize);

  return (MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpKeepAliveMsg */

/*
 *  decode
 */
int Mpls_decodeLdpKeepAliveMsg
  (mplsLdpKeepAlMsg_t * keepAlive, u_char * buff, int bufSize) {
  int decodedSize = 0;

  memset(keepAlive, 0, MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN);
  decodedSize = Mpls_decodeLdpBaseMsg(&(keepAlive->baseMsg), buff, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for keep alive on %d bytes\n", decodedSize);

  if (keepAlive->baseMsg.flags.flags.msgType != MPLS_KEEPAL_MSGTYPE) {
    PRINT_ERR("Not the right message type; expected keep alive and got %x\n",
      keepAlive->baseMsg.flags.flags.msgType);
    return MPLS_MSGTYPEERROR;
  }

  return (MPLS_MSGIDFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_decodeLdpKeepAliveMsg */

/* 
 * Encode for Address List TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpAdrTlv(mplsLdpAdrTlv_t * adrList, u_char * buff, int bufSize)
{
  int i, numberAdr;
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_short tempLength;           /* to store the tlv length for

                                   later use */

  if (MPLS_TLVFIXLEN + (int)(adrList->baseTlv.length) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  tempLength = adrList->baseTlv.length;
  /*
   *  encode for tlv
   */
  encodedSize = Mpls_encodeLdpTlv(&(adrList->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in AdrList\n");
    return MPLS_ENC_TLVERROR;
  }

  tempBuf += encodedSize;

  adrList->addrFamily = htons(adrList->addrFamily);

  numberAdr = (tempLength - sizeof(u_short)) / sizeof(u_int);
  for (i = 0; i < numberAdr; i++) {
    adrList->address[i] = htonl(adrList->address[i]);
  }

  MEM_COPY(tempBuf, (u_char *) & adrList->addrFamily, sizeof(u_short));

  tempBuf += sizeof(u_short);

  MEM_COPY(tempBuf,
    (u_char *) & adrList->address, tempLength - sizeof(u_short));

  return (tempLength + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpAdrTlv */

/*
 *  decode
 *
 *  Note: the tlvLength is used to specify what is the length of the 
 *        encoding in the AdrTlv.
 */
int Mpls_decodeLdpAdrTlv
  (mplsLdpAdrTlv_t * adrList, u_char * buff, int bufSize, u_short tlvLength) {
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  int i, numberAdr;

  if ((int)tlvLength > bufSize) {
    /* not enough data for Adr list tlv */
    PRINT_ERR("failed decoding AddrList tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /*
   *  decode for the addressFamily and addresses of the address list
   */
  MEM_COPY((u_char *) & adrList->addrFamily, tempBuf, sizeof(u_short));
  tempBuf += sizeof(u_short);

  adrList->addrFamily = ntohs(adrList->addrFamily);

  MEM_COPY((u_char *) & adrList->address, tempBuf, tlvLength - sizeof(u_short));

  numberAdr = (tlvLength - sizeof(u_short)) / sizeof(u_int);
  for (i = 0; i < numberAdr; i++) {
    adrList->address[i] = ntohl(adrList->address[i]);
  }

  return tlvLength;

}                               /* End: Mpls_decodeLdpAdrTlv */

/* 
 * Encode for Address / Address Withdraw messages
 */

/*
 *  encode
 */
int Mpls_encodeLdpAdrMsg(mplsLdpAdrMsg_t * addrMsg, u_char * buff, int bufSize)
{
  mplsLdpAdrMsg_t addrMsgCopy;
  int encodedSize = 0;
  u_int totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  /* check the length of the messageId + param */
  if ((int)(addrMsg->baseMsg.msgLength) + MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("failed to encode the address msg: BUFFER TOO SMALL\n");
    return MPLS_ENC_BUFFTOOSMALL;
  }

  addrMsgCopy = *addrMsg;

  /*
   *  encode the base part of the pdu message
   */
  encodedSize = Mpls_encodeLdpBaseMsg(&(addrMsgCopy.baseMsg), tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_BASEMSGERROR;
  }
  PRINT_OUT("Encode BaseMsg for address on %d bytes\n", encodedSize);
  tempBuf += encodedSize;
  totalSize += encodedSize;

  /*
   *  encode the address list tlv if any
   */
  if (addrMsg->adrListTlvExists) {
    encodedSize = Mpls_encodeLdpAdrTlv(&(addrMsgCopy.addressList),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_ADRLISTERROR;
    }
    PRINT_OUT("Encoded for AddressList Tlv %d bytes\n", encodedSize);
  }

  return (addrMsg->baseMsg.msgLength + MPLS_TLVFIXLEN);

}                               /* End: */

/*
 *  decode
 */
int Mpls_decodeLdpAdrMsg(mplsLdpAdrMsg_t * addrMsg, u_char * buff, int bufSize)
{
  int decodedSize = 0;
  u_int totalSize = 0;
  u_int stopLength = 0;
  u_int totalSizeParam = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  mplsLdpTlv_t tlvTemp;

  /*
   *  decode the base part of the pdu message
   */
  memset(addrMsg, 0, sizeof(mplsLdpAdrMsg_t));
  decodedSize = Mpls_decodeLdpBaseMsg(&(addrMsg->baseMsg), tempBuf, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for address msg on %d bytes\n", decodedSize);

  if ((addrMsg->baseMsg.flags.flags.msgType != MPLS_ADDR_MSGTYPE) &&
    (addrMsg->baseMsg.flags.flags.msgType != MPLS_ADDRWITH_MSGTYPE)) {
    PRINT_ERR("Not the right message type; expected adr and got %x\n",
      addrMsg->baseMsg.flags.flags.msgType);
    return MPLS_MSGTYPEERROR;
  }

  tempBuf += decodedSize;
  totalSize += decodedSize;

  if (bufSize - totalSize <= 0) {
    /* nothing left for decoding */
    PRINT_ERR("Adr msg does not have anything beside base msg\n");
    return totalSize;
  }

  PRINT_OUT("bufSize = %d,  totalSize = %d, addrMsg->baseMsg.msgLength = %d\n",
    bufSize, totalSize, addrMsg->baseMsg.msgLength);

  /* Have to check the baseMsg.msgLength to know when to finish.
   * We finsh when the totalSizeParam is >= to the base message length - the
   * message id length (4) 
   */

  stopLength = addrMsg->baseMsg.msgLength - MPLS_MSGIDFIXLEN;
  while (stopLength > totalSizeParam) {
    /*
     *  decode the tlv to check what's next
     */
    memset(&tlvTemp, 0, MPLS_TLVFIXLEN);
    decodedSize = Mpls_decodeLdpTlv(&tlvTemp, tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      /* something wrong */
      PRINT_ERR("ADR msg decode failed for tlv\n");
      return MPLS_DEC_TLVERROR;
    }

    tempBuf += decodedSize;
    totalSize += decodedSize;
    totalSizeParam += decodedSize;

    switch (tlvTemp.flags.flags.tBit) {
      case MPLS_ADDRLIST_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpAdrTlv(&(addrMsg->addressList),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding AdrList tlv from adr msg\n");
            return MPLS_DEC_ADRLISTERROR;
          }
          PRINT_OUT("Decoded for ADRLIST %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          addrMsg->adrListTlvExists = 1;
          addrMsg->addressList.baseTlv = tlvTemp;
          break;
        }
      default:
        {
          PRINT_ERR("Found wrong tlv type while decoding adr msg (%x)\n",
            tlvTemp.flags.flags.tBit);
          if (tlvTemp.flags.flags.uBit == 1) {
            /* ignore the Tlv and continue processing */
            tempBuf += tlvTemp.length;
            totalSize += tlvTemp.length;
            totalSizeParam += tlvTemp.length;
            break;
          } else {
            /* drop the message; return error */
            return MPLS_TLVTYPEERROR;
          }
        }
    }                           /* switch type */

  }                             /* while */

  PRINT_OUT("totalsize for Mpls_decodeLdpAdrMsg is %d\n", totalSize);

  return totalSize;

}                               /* End: Mpls_decodeLdpAdrMsg */

/* 
 * Encode for FEC ELEMENT 
 */

/*
 *  encode
 */
int Mpls_encodeLdpFecAdrEl
  (mplsFecElement_t * fecAdrEl, u_char * buff, int bufSize, u_char type) {
  int encodedSize = 0;
  u_char *tempBuf = buff;

  switch (type) {
    case MPLS_WC_FEC:
      {
        if (MPLS_FEC_ELEMTYPELEN > bufSize) {
          return MPLS_ENC_BUFFTOOSMALL;
        }
        *buff = fecAdrEl->wildcardEl.type;
        encodedSize = MPLS_FEC_ELEMTYPELEN;
        break;
      }
    case MPLS_PREFIX_FEC:
      {
        int preLenOctets;

        fecAdrEl->addressEl.addressFam = htons(fecAdrEl->addressEl.addressFam);
        fecAdrEl->addressEl.address = htonl(fecAdrEl->addressEl.address);
        preLenOctets = (int)(fecAdrEl->addressEl.preLen / 8) +
          ((int)(fecAdrEl->addressEl.preLen % 8) > 0 ? 1 : 0);

        encodedSize = MPLS_FEC_ADRFAMLEN + MPLS_FEC_ELEMTYPELEN +
          MPLS_FEC_PRELENLEN + preLenOctets;

        if (encodedSize > bufSize) {
          return MPLS_ENC_BUFFTOOSMALL;
        }
        *tempBuf = fecAdrEl->addressEl.type;
        tempBuf++;              /* for MPLS_FEC_ELEMTYPELEN */

        MEM_COPY(tempBuf,
          (u_char *) & (fecAdrEl->addressEl.addressFam), MPLS_FEC_ADRFAMLEN);
        tempBuf += MPLS_FEC_ADRFAMLEN;

        *tempBuf = fecAdrEl->addressEl.preLen;
        tempBuf++;              /* for MPLS_FEC_PRELENLEN */

        MEM_COPY(tempBuf, (u_char *) & (fecAdrEl->addressEl.address),
          preLenOctets);
        break;
      }
    case MPLS_HOSTADR_FEC:
      {
        fecAdrEl->addressEl.addressFam = htons(fecAdrEl->addressEl.addressFam);
        fecAdrEl->addressEl.address = htonl(fecAdrEl->addressEl.address);

        encodedSize = MPLS_FEC_ADRFAMLEN + MPLS_FEC_ELEMTYPELEN +
          MPLS_FEC_PRELENLEN + fecAdrEl->addressEl.preLen;

        if (encodedSize > bufSize) {
          return MPLS_ENC_BUFFTOOSMALL;
        }
        *tempBuf = fecAdrEl->addressEl.type;
        tempBuf++;              /* for MPLS_FEC_ELEMTYPELEN */

        MEM_COPY(tempBuf,
          (u_char *) & (fecAdrEl->addressEl.addressFam), MPLS_FEC_ADRFAMLEN);
        tempBuf += MPLS_FEC_ADRFAMLEN;

        *tempBuf = fecAdrEl->addressEl.preLen;
        tempBuf++;              /* for MPLS_FEC_PRELENLEN */

        MEM_COPY(tempBuf,
          (u_char *) & (fecAdrEl->addressEl.address),
          fecAdrEl->addressEl.preLen);
        break;
      }
    case MPLS_CRLSP_FEC:
      {
        if (MPLS_FEC_CRLSPLEN > bufSize) {
          return MPLS_ENC_BUFFTOOSMALL;
        }
        fecAdrEl->crlspEl.res1 = 0;
        fecAdrEl->crlspEl.res2 = 0;
        MEM_COPY(tempBuf, (u_char *) & (fecAdrEl->crlspEl), MPLS_FEC_CRLSPLEN);
        encodedSize = MPLS_FEC_CRLSPLEN;
        break;
      }
    case MPLS_PW_ID_FEC: //add by timothy
      {
        //int preLenOctets;
        fecAdrEl->pwidEl.flags.mark=htons(fecAdrEl->pwidEl.flags.mark);
        fecAdrEl->pwidEl.group_id=htonl(fecAdrEl->pwidEl.group_id);
        fecAdrEl->pwidEl.pw_id=htonl(fecAdrEl->pwidEl.pw_id);
        //preLenOctets = (int)(fecAdrEl->pwidEl.pw_info_Len / 8)+
        //  ((int)(fecAdrEl->pwidEl.pw_info_Len % 8) > 0 ? 1: 0);
        encodedSize=MPLS_FEC_ELEMTYPELEN+MPLS_FEC_PWIDTYPELEN+MPLS_FEC_PRELENLEN+
                   MPLS_FEC_PWIDGROUPIDLEN+MPLS_FEC_PWIDPWIDLEN;
       
        if (encodedSize > bufSize) {
          return MPLS_ENC_BUFFTOOSMALL;
        }
        *tempBuf=fecAdrEl->pwidEl.pw_tlv;
        tempBuf++;
        MEM_COPY(tempBuf,(u_char *)&(fecAdrEl->pwidEl.flags.mark),
                 MPLS_FEC_PWIDTYPELEN);
        tempBuf+=MPLS_FEC_PWIDTYPELEN;
        *tempBuf=fecAdrEl->pwidEl.pw_info_Len;
        tempBuf++;
        MEM_COPY(tempBuf,(u_char *)&(fecAdrEl->pwidEl.group_id),
                 MPLS_FEC_PWIDGROUPIDLEN);
        tempBuf+=MPLS_FEC_PWIDGROUPIDLEN;
        MEM_COPY(tempBuf,(u_char *)&(fecAdrEl->pwidEl.pw_id),
                 MPLS_FEC_PWIDPWIDLEN);
        tempBuf+=MPLS_FEC_PWIDPWIDLEN;
        break;
      }
    default:
      {
        PRINT_ERR("Found wrong FEC type while encoding FEC elem (%d)\n", type);
        return MPLS_ENC_FECELEMERROR;
        break;
      }
  }                             /* end: switch */

  return encodedSize;

}                               /* End: Mpls_encodeLdpFecAdrEl */

/*
 *  decode
 */
int Mpls_decodeLdpFecAdrEl
  (mplsFecElement_t * fecAdrEl, u_char * buff, int bufSize, u_char type) {
  int decodedSize = 0;
  u_char *tempBuff = buff;
  u_int preLen = 0; extern int PW_SIGNALING_FLAG;//testing

  switch (type) {
    case MPLS_WC_FEC:
      {
        fecAdrEl->wildcardEl.type = *buff;
        decodedSize = MPLS_FEC_ELEMTYPELEN;
        break;
      }
    case MPLS_PREFIX_FEC:
      {
        //printf("Prefix Decoding\n");//testng 
        decodedSize = MPLS_FEC_ADRFAMLEN + MPLS_FEC_ELEMTYPELEN +
          MPLS_FEC_PRELENLEN;
        //printf("Prefix decodesize: %d\n",decodedSize);//testing
        if (decodedSize > bufSize) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        fecAdrEl->addressEl.type = *tempBuff;
        tempBuff++;             /* for MPLS_FEC_ELEMTYPELEN */

        MEM_COPY((u_char *) & (fecAdrEl->addressEl.addressFam),
          tempBuff, MPLS_FEC_ADRFAMLEN);
        tempBuff += MPLS_FEC_ADRFAMLEN;

        fecAdrEl->addressEl.preLen = *tempBuff;
        tempBuff++;             /* for MPLS_FEC_PRELENLEN */

        fecAdrEl->addressEl.addressFam = ntohs(fecAdrEl->addressEl.addressFam);

        /* now we get the prefix; we need to use the preLen which was
           decoded from buff */

        preLen = (int)(fecAdrEl->addressEl.preLen / 8) +
          ((int)(fecAdrEl->addressEl.preLen % 8) > 0 ? 1 : 0);

        if (fecAdrEl->addressEl.preLen > sizeof(u_int) * 8) {
          /* error - the length cannot exeed 32 bits */
          /* skip the FEC and return error code */
          /* fill in the preLen field to the number of bytes for this
             fec; we need it to know how much to skip from the buffer 
             when we do the decoding for the following fec element */
          fecAdrEl->addressEl.preLen = preLen + decodedSize;
          return MPLS_FECERROR;
        }
        if ((int)preLen > bufSize - decodedSize) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        MEM_COPY((u_char *) & (fecAdrEl->addressEl.address), tempBuff, preLen);

        fecAdrEl->addressEl.address = ntohl(fecAdrEl->addressEl.address);
        decodedSize += preLen;
        break;
      }
    case MPLS_HOSTADR_FEC:
      {
        decodedSize = MPLS_FEC_ADRFAMLEN + MPLS_FEC_ELEMTYPELEN +
          MPLS_FEC_PRELENLEN;
        if (decodedSize > bufSize) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        fecAdrEl->addressEl.type = *tempBuff;
        tempBuff++;             /* for MPLS_FEC_ELEMTYPELEN */

        MEM_COPY((u_char *) & (fecAdrEl->addressEl.addressFam),
          tempBuff, MPLS_FEC_ADRFAMLEN);
        tempBuff += MPLS_FEC_ADRFAMLEN;

        fecAdrEl->addressEl.preLen = *tempBuff;
        tempBuff++;             /* for MPLS_FEC_PRELENLEN */

        fecAdrEl->addressEl.addressFam = ntohs(fecAdrEl->addressEl.addressFam);

        /* now we get the host address; we need to use the preLen which was
           decoded from buff */

        preLen = fecAdrEl->addressEl.preLen;
        if (fecAdrEl->addressEl.preLen > sizeof(u_int)) {
          /* error - the length cannot exeed 32 bits */
          /* skip the FEC and return error code */
          /* fill in the preLen field to the number of bytes for this
             fec; we need it to know how much to skip from the buffer 
             when we do the decoding for the following fec element */
          fecAdrEl->addressEl.preLen = preLen + decodedSize;
          return MPLS_FECERROR;
        }
        if ((int)preLen > bufSize - decodedSize) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        MEM_COPY((u_char *) & (fecAdrEl->addressEl.address), tempBuff, preLen);

        fecAdrEl->addressEl.address = ntohl(fecAdrEl->addressEl.address);
        decodedSize += preLen;
        break;
      }
    case MPLS_CRLSP_FEC:
      {
        if (MPLS_FEC_CRLSPLEN > bufSize) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        MEM_COPY((u_char *) & (fecAdrEl->crlspEl), tempBuff, MPLS_FEC_CRLSPLEN);
        decodedSize = MPLS_FEC_CRLSPLEN;
        break;
      }
    case MPLS_PW_ID_FEC: //add by timothy
      {
        //PW_SIGNALING_FLAG=1;
        printf("Enter PW decode\n"); //testing
        decodedSize=MPLS_FEC_ELEMTYPELEN+MPLS_FEC_PWIDTYPELEN+MPLS_FEC_PRELENLEN+
                   MPLS_FEC_PWIDGROUPIDLEN+MPLS_FEC_PWIDPWIDLEN;
        
        if (decodedSize > bufSize) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        fecAdrEl->pwidEl.pw_tlv=*tempBuff;
        tempBuff++;
        MEM_COPY((u_char *)&(fecAdrEl->pwidEl.flags.mark),tempBuff
                  ,MPLS_FEC_PWIDTYPELEN);
        fecAdrEl->pwidEl.flags.mark=ntohs(fecAdrEl->pwidEl.flags.mark);
        tempBuff+=MPLS_FEC_PWIDTYPELEN;
        fecAdrEl->pwidEl.pw_info_Len=*tempBuff;
        printf("Len: %02x\n",fecAdrEl->pwidEl.pw_info_Len);
        tempBuff++;
        //fecAdrEl->pwidEl.group_id=*tempBuff;
        MEM_COPY((u_char *)&(fecAdrEl->pwidEl.group_id),tempBuff,
                 MPLS_FEC_PWIDGROUPIDLEN);
        fecAdrEl->pwidEl.group_id=ntohl(fecAdrEl->pwidEl.group_id);
        printf("group id: %08x\n",fecAdrEl->pwidEl.group_id);

        tempBuff+=MPLS_FEC_PWIDGROUPIDLEN;
        //fecAdrEl->pwidEl.pw_id=*tempBuff;
        MEM_COPY((u_char *)&(fecAdrEl->pwidEl.pw_id),tempBuff,
                 MPLS_FEC_PWIDPWIDLEN);
        fecAdrEl->pwidEl.pw_id=ntohl(fecAdrEl->pwidEl.pw_id);
        printf("pw id: %08x\n",fecAdrEl->pwidEl.pw_id);
        tempBuff+=MPLS_FEC_PWIDPWIDLEN;

        //fecAdrEl->pwidEl.flags.mark=ntohs(fecAdrEl->pwidEl.flags.mark);
        //preLen=(int)(fecAdrEl->pwidEl.pw_info_Len / 8)+
        //       ((int)(fecAdrEl->pwidEl.pw_info_Len % 8) > 0 ? 1: 0);
        //if (fecAdrEl->pwidEl.pw_info_Len > sizeof(u_int) * 8) {
        //  fecAdrEl->pwidEl.pw_info_Len = preLen + decodedSize;
        //  return MPLS_FECERROR;
        //}
        //if ((int)(preLen) > bufSize - decodedSize) {
        //  return MPLS_DEC_BUFFTOOSMALL;
        //}  
        //MEM_COPY((u_char *)&(fecAdrEl->pwidEl.group_id),tempBuff,
        //         MPLS_FEC_PWIDGROUPIDLEN);
        //MEM_COPY((u_char *)&(fecAdrEl->pwidEl.pw_id),tempBuff,
        //         MPLS_FEC_PWIDPWIDLEN);
        //fecAdrEl->pwidEl.group_id=ntohl(fecAdrEl->pwidEl.group_id);
        //fecAdrEl->pwidEl.pw_id=ntohl(fecAdrEl->pwidEl.pw_id);
        //decodedSize += preLen;
        break;
      }
    default:
      {
        PRINT_ERR("Found wrong FEC type while decoding FEC elem (%d)\n", type);
        return MPLS_DEC_FECELEMERROR;
        break;
      }
  }                             /* end: switch */

  return decodedSize;

}                               /* End: Mpls_decodeLdpFecAdrEl */

/* 
 * Encode for FEC TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpFecTlv(mplsLdpFecTlv_t * fecTlv, u_char * buff, int bufSize)
{
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_short i;
  int encodedSize = 0;
  u_int fecElSize = 0;          /* used to compute the sum of

                                   all fec elements */

  if ((int)fecTlv->baseTlv.length + MPLS_TLVFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* check how many fec elements we have */
  if (fecTlv->numberFecElements > MPLS_MAXNUMFECELEMENT) {
    /* too many fec elem; need to increase MPLS_MAXNUMFECELEMENT */
    PRINT_ERR("Too many fec elem\n");
    return MPLS_FECTLVERROR;
  }

  for (i = 0; i < fecTlv->numberFecElements; i++) {
    if ((fecTlv->fecElemTypes[i] == MPLS_WC_FEC) &&
      (fecTlv->numberFecElements != 1)) {
      return MPLS_WC_FECERROR;
    }
  }

  /*
   *  encode for tlv
   */
  encodedSize = Mpls_encodeLdpTlv(&(fecTlv->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in FEC tlv\n");
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;
  fecElSize += encodedSize;

  /* encode now the FEC elements; check if wc exists; if it is there
     then it should be the only element */

  for (i = 0; i < fecTlv->numberFecElements; i++) {
    encodedSize = Mpls_encodeLdpFecAdrEl(&(fecTlv->fecElArray[i]),
      tempBuf, bufSize - fecElSize, fecTlv->fecElemTypes[i]);
    if (encodedSize < 0) {
      return MPLS_ENC_FECELEMERROR;
    }
    tempBuf += encodedSize;
    fecElSize += encodedSize;
  }

  return fecElSize;

}                               /* End: Mpls_encodeLdpFecTlv */

/*
 *  decode
 */
int Mpls_decodeLdpFecTlv
  (mplsLdpFecTlv_t * fecTlv, u_char * buff, int bufSize, u_short tlvLength) {
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  int decodedSize = 0;
  u_int fecElSize = 0;          /* used to compute the sum of

                                   all fec elements */
  u_short i = 0;
  u_char type;

  if ((int)tlvLength > bufSize) {
    /* not enough data for Fec elements tlv */
    PRINT_ERR("failed decoding FEC elements tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /*
   *  decode for the FEC elements; check also that if we have a wc element,
   *  it is the only element encoded in the FEC;
   */
  type = *tempBuf;              /* first thing after the TLV base should be the type
                                   of the fec element */

  fecTlv->numberFecElements = 0;

  while (tlvLength > fecElSize) {

    /* check how many fec elements we have */
    if (fecTlv->numberFecElements > (u_short) (MPLS_MAXNUMFECELEMENT - 1)) {
      /* too many fec elem; need to increase MPLS_MAXNUMFECELEMENT */
      PRINT_ERR("Too many fec elem\n");
      return MPLS_FECTLVERROR;
    }

    decodedSize = Mpls_decodeLdpFecAdrEl(&(fecTlv->fecElArray[i]),
      tempBuf, bufSize - fecElSize, type);
    if ((decodedSize < 0) && (decodedSize != MPLS_FECERROR)) {
      return MPLS_DEC_FECELEMERROR;
    } else {
      /* if the element had wrong preLen value, just skip it */
      if (decodedSize != MPLS_FECERROR) {
        fecTlv->fecElemTypes[i] = type;  printf("FEC Type: %x\n",type);//testing
        fecTlv->numberFecElements++;
        i++;                           

        tempBuf += decodedSize;
        fecElSize += decodedSize;
      } else {
        /* the preLen was filled with the total length
           of the fec element to be skipped */
        tempBuf += fecTlv->fecElArray[i].addressEl.preLen;
        fecElSize += fecTlv->fecElArray[i].addressEl.preLen;
      }
    }

    /* get the type of the next element */
    type = *tempBuf;

  }                             /* end while */

  for (i = 0; i < fecTlv->numberFecElements; i++) {
    if ((fecTlv->fecElemTypes[i] == MPLS_WC_FEC) &&
      (fecTlv->numberFecElements != 1)) {
      return MPLS_WC_FECERROR;
    }
  }

  return fecElSize;             /* fecElSize should be equal to tlvLength */

}                               /* End: Mpls_decodeLdpFecTlv */

/* 
 * Encode for Generic label TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpGenLblTlv
  (mplsLdpGenLblTlv_t * genLbl, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_TLVFIXLEN + (int)(genLbl->baseTlv.length) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /*
   *  encode for tlv
   */
  encodedSize = Mpls_encodeLdpTlv(&(genLbl->baseTlv), tempBuf, bufSize);
  if (encodedSize < 0) {
    PRINT_ERR("failed encoding the tlv in Generic Label\n");
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  genLbl->label = htonl(genLbl->label);

  MEM_COPY(tempBuf, (u_char *) & (genLbl->label), MPLS_LBLFIXLEN);

  return (MPLS_TLVFIXLEN + MPLS_LBLFIXLEN);

}                               /* End: Mpls_encodeLdpGenLblTlv */

/*
 *  decode
 */
int Mpls_decodeLdpGenLblTlv
  (mplsLdpGenLblTlv_t * genLbl, u_char * buff, int bufSize) {
  if (MPLS_LBLFIXLEN > bufSize) {
    /* not enough data for generic label tlv */
    PRINT_ERR("failed decoding Generic tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /*
   *  decode the label
   */
  MEM_COPY((u_char *) & (genLbl->label), buff, MPLS_LBLFIXLEN);

  genLbl->label = ntohl(genLbl->label);
  printf("Decode Label: %d\n",genLbl->label);//testing

  return MPLS_LBLFIXLEN;

}                               /* End: Mpls_decodeLdpGenLblTlv */

/* 
 * Encode for ATM Label TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpAtmLblTlv
  (mplsLdpAtmLblTlv_t * atmLblTlv, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_char *atmLblPtr;

  if (MPLS_TLVFIXLEN + MPLS_LBLFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  atmLblPtr = (u_char *) atmLblTlv;

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(atmLblTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;
  atmLblPtr += encodedSize;

  /* 
   *  encode for flags
   */
  atmLblTlv->flags.flags.res = 0;
  atmLblTlv->flags.mark = htons(atmLblTlv->flags.mark);
  atmLblTlv->vci = htons(atmLblTlv->vci);

  MEM_COPY(tempBuf, atmLblPtr, MPLS_LBLFIXLEN);

  return (MPLS_LBLFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpAtmLblTlv */

/*
 *  decode
 */
int Mpls_decodeLdpAtmLblTlv
  (mplsLdpAtmLblTlv_t * atmLblTlv, u_char * buff, int bufSize) {
  u_char *atmLblTlvPtr;

  if (MPLS_LBLFIXLEN > bufSize) {
    /* not enough data for AtmLabel */
    PRINT_ERR("failed decoding atm label tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  atmLblTlvPtr = (u_char *) atmLblTlv;
  atmLblTlvPtr += MPLS_TLVFIXLEN; /* to point after the Tlv which was
                                     decoded before we reach here */
  /*
   *  decode for the rest of the AtmLblTlv 
   */
  MEM_COPY(atmLblTlvPtr, buff, MPLS_LBLFIXLEN);

  atmLblTlv->flags.mark = ntohs(atmLblTlv->flags.mark);
  atmLblTlv->vci = ntohs(atmLblTlv->vci);

  return MPLS_LBLFIXLEN;

}                               /* End: Mpls_decodeLdpAtmLblTlv */

/* 
 * Encode for FR Label TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpFrLblTlv
  (mplsLdpFrLblTlv_t * frLblTlv, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_TLVFIXLEN + MPLS_LBLFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(frLblTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  /* 
   *  encode for flags
   */
  frLblTlv->flags.mark = htonl(frLblTlv->flags.mark);

  MEM_COPY(tempBuf, (u_char *) & (frLblTlv->flags.mark), MPLS_LBLFIXLEN);

  return (MPLS_LBLFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpFrLblTlv */

/*
 *  decode
 */
int Mpls_decodeLdpFrLblTlv
  (mplsLdpFrLblTlv_t * frLblTlv, u_char * buff, int bufSize) {
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_LBLFIXLEN > bufSize) {
    /* not enough data for FrLabel */
    PRINT_ERR("failed decoding fr label tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /*
   *  decode for the rest of the FrLblTlv 
   */
  MEM_COPY((u_char *) & (frLblTlv->flags.mark), tempBuf, MPLS_LBLFIXLEN);

  frLblTlv->flags.mark = ntohl(frLblTlv->flags.mark);

  return MPLS_LBLFIXLEN;

}                               /* End: Mpls_decodeLdpFrLblTlv */

/* 
 * Encode for Hop Count TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpHopTlv
  (mplsLdpHopTlv_t * hopCountTlv, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_TLVFIXLEN + MPLS_HOPCOUNTFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(hopCountTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  /* 
   *  encode for hop count value 
   */
  *tempBuf = hopCountTlv->hcValue;

  return (MPLS_HOPCOUNTFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpFrLblTlv */

/*
 *  decode
 */
int Mpls_decodeLdpHopTlv
  (mplsLdpHopTlv_t * hopCountTlv, u_char * buff, int bufSize) {
  if (MPLS_HOPCOUNTFIXLEN > bufSize) {
    /* not enough data for hop count value */
    PRINT_ERR("failed decoding hop count tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /*
   *  decode for the hop count value
   */
  hopCountTlv->hcValue = *buff;

  return MPLS_HOPCOUNTFIXLEN;

}                               /* End: Mpls_decodeLdpHopTlv */

/* 
 * Encode for Lbl Msg Id TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpLblMsgIdTlv
  (mplsLdpLblMsgIdTlv_t * lblMsgIdTlv, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_TLVFIXLEN + MPLS_LBLFIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(lblMsgIdTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  /* 
   *  encode for msg id 
   */

  lblMsgIdTlv->msgId = htonl(lblMsgIdTlv->msgId);

  MEM_COPY(tempBuf, (u_char *) & (lblMsgIdTlv->msgId), MPLS_LBLFIXLEN);

  return (MPLS_LBLFIXLEN + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpFrLblTlv */

/*
 *  decode
 */
int Mpls_decodeLdpLblMsgIdTlv
  (mplsLdpLblMsgIdTlv_t * lblMsgIdTlv, u_char * buff, int bufSize) {
  if (MPLS_LBLFIXLEN > bufSize) {
    /* not enough data for msg id tlv */
    PRINT_ERR("failed decoding lbl msg id tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  /*
   *  decode for the rest of the LblMsgId Tlv 
   */
  MEM_COPY((u_char *) & (lblMsgIdTlv->msgId), buff, MPLS_LBLFIXLEN);

  lblMsgIdTlv->msgId = ntohl(lblMsgIdTlv->msgId);

  return MPLS_LBLFIXLEN;

}                               /* End: Mpls_decodeLdpLblMsgIdTlv */

/* 
 * Encode for Path Vector TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpPathVectorTlv
  (mplsLdpPathTlv_t * pathVectorTlv, u_char * buff, int bufSize) {
  u_char *pathVectorTlvPtr;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  int encodedSize = 0;
  u_int i, numLsrIds;
  u_short tempLength;           /* to store the tlv length for

                                   later use */

  if (MPLS_TLVFIXLEN + (int)(pathVectorTlv->baseTlv.length) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  pathVectorTlvPtr = (u_char *) pathVectorTlv;
  tempLength = pathVectorTlv->baseTlv.length;
  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(pathVectorTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;
  pathVectorTlvPtr += encodedSize;

  /* 
   *  encode for labels
   */

  if (tempLength % MPLS_LBLFIXLEN != 0) {
    return MPLS_PATHVECTORERROR;
  }

  numLsrIds = tempLength / MPLS_LBLFIXLEN;
  if (numLsrIds > MPLS_MAXHOPSNUMBER) {
    /* too many lsrIds; need to increase MPLS_MAXHOPSNUMBER */
    PRINT_ERR("Too many lsr ids (%d)\n", numLsrIds);
    return MPLS_PATHVECTORERROR;
  }

  for (i = 0; i < numLsrIds; i++) {
    pathVectorTlv->lsrId[i] = htonl(pathVectorTlv->lsrId[i]);
  }

  MEM_COPY(tempBuf, pathVectorTlvPtr, tempLength);

  return (tempLength + MPLS_TLVFIXLEN);

}                               /* End: Mpls_encodeLdpPathVectorTlv */

/*
 *  decode
 */
int Mpls_decodeLdpPathVectorTlv
  (mplsLdpPathTlv_t * pathVectorTlv,
  u_char * buff, int bufSize, u_short tlvLength) {
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_int i, numLsrIds;

  if (MPLS_LBLFIXLEN > bufSize) {
    /* not enough data for msg id tlv */
    PRINT_ERR("failed decoding lbl msg id tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  if (tlvLength % MPLS_LBLFIXLEN != 0) {
    PRINT_ERR("Wrong length for Path vector tlv (%d)\n", tlvLength);
    return MPLS_PATHVECTORERROR;
  }

  numLsrIds = tlvLength / MPLS_LBLFIXLEN;
  if (numLsrIds > MPLS_MAXHOPSNUMBER) {
    /* too many lsrIds; need to increase MPLS_MAXHOPSNUMBER */
    PRINT_ERR("Too many lsr ids (%d)\n", numLsrIds);
    return MPLS_PATHVECTORERROR;
  }

  /*
   *  decode for the rest of the LblMsgId Tlv 
   */
  MEM_COPY((u_char *) (pathVectorTlv->lsrId), tempBuf, tlvLength);

  for (i = 0; i < numLsrIds; i++) {
    pathVectorTlv->lsrId[i] = ntohl(pathVectorTlv->lsrId[i]);
  }

  return tlvLength;

}                               /* End: Mpls_decodeLdpPathVectorTlv */

/* 
 * Encode for Label Mapping Message
 */

/*
 *  encode
 */
int Mpls_encodeLdpLblMapMsg
  (mplsLdpLblMapMsg_t * lblMapMsg, u_char * buff, int bufSize) {
  mplsLdpLblMapMsg_t lblMapMsgCopy;
  int encodedSize = 0;
  u_int totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  /* check the length of the messageId + param */
  if ((int)(lblMapMsg->baseMsg.msgLength) + MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("failed to encode the lbl mapping msg: BUFFER TOO SMALL\n");
    return MPLS_ENC_BUFFTOOSMALL;
  }

  lblMapMsgCopy = *lblMapMsg;

  /*
   *  encode the base part of the pdu message
   */
  encodedSize = Mpls_encodeLdpBaseMsg(&(lblMapMsgCopy.baseMsg),
    tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_BASEMSGERROR;
  }
  PRINT_OUT("Encode BaseMsg for label mapping on %d bytes\n", encodedSize);
  tempBuf += encodedSize;
  totalSize += encodedSize;

  /*
   *  encode the tlv if any
   */
  if (lblMapMsgCopy.fecTlvExists) {
    encodedSize = Mpls_encodeLdpFecTlv(&(lblMapMsgCopy.fecTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_FECERROR;
    }
    PRINT_OUT("Encoded for FEC Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  if (lblMapMsgCopy.genLblTlvExists) {
    encodedSize = Mpls_encodeLdpGenLblTlv(&(lblMapMsgCopy.genLblTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_GENLBLERROR;
    }
    PRINT_OUT("Encoded for Generic Label Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblMapMsgCopy.atmLblTlvExists) {
    encodedSize = Mpls_encodeLdpAtmLblTlv(&(lblMapMsgCopy.atmLblTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_MAPATMERROR;
    }
    PRINT_OUT("Encoded for Atm Label Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblMapMsgCopy.frLblTlvExists) {
    encodedSize = Mpls_encodeLdpFrLblTlv(&(lblMapMsgCopy.frLblTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_FRLBLERROR;
    }
    PRINT_OUT("Encoded for Fr Label Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblMapMsgCopy.hopCountTlvExists) {
    encodedSize = Mpls_encodeLdpHopTlv(&(lblMapMsgCopy.hopCountTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_HOPCOUNTERROR;
    }
    PRINT_OUT("Encoded for Hop Count Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblMapMsgCopy.pathVecTlvExists) {
    encodedSize = Mpls_encodeLdpPathVectorTlv(&(lblMapMsgCopy.pathVecTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_PATHVECERROR;
    }
    PRINT_OUT("Encoded for Path Vector Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblMapMsgCopy.lblMsgIdTlvExists) {
    encodedSize = Mpls_encodeLdpLblMsgIdTlv(&(lblMapMsgCopy.lblMsgIdTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_LBLMSGIDERROR;
    }
    PRINT_OUT("Encoded for lbl request msg id Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblMapMsgCopy.trafficTlvExists) {
    encodedSize = Mpls_encodeLdpTrafficTlv(&(lblMapMsgCopy.trafficTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_TRAFFICERROR;
    }
    PRINT_OUT("Encoded for Traffic Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblMapMsgCopy.lspidTlvExists) {
    encodedSize = Mpls_encodeLdpLspIdTlv(&(lblMapMsgCopy.lspidTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_LSPIDERROR;
    }
    PRINT_OUT("Encoded for LSPID Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End: Mpls_encodeLdpLblMapMsg */

/*
 *  decode
 */

int Mpls_decodeLdpLblMapMsg
  (mplsLdpLblMapMsg_t * lblMapMsg, u_char * buff, int bufSize) {
  int decodedSize = 0;
  u_int totalSize = 0;
  u_int stopLength = 0;
  u_int totalSizeParam = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  mplsLdpTlv_t tlvTemp;
  extern int PW_SIGNALING_FLAG;//testing
  /*
   *  decode the base part of the pdu message
   */
  memset(lblMapMsg, 0, sizeof(mplsLdpLblMapMsg_t));
  decodedSize = Mpls_decodeLdpBaseMsg(&(lblMapMsg->baseMsg), tempBuf, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for Lbl Mapping on %d bytes\n", decodedSize);

  if (lblMapMsg->baseMsg.flags.flags.msgType != MPLS_LBLMAP_MSGTYPE) {
    PRINT_ERR("Not the right message type; expected lbl map and got %x\n",
      lblMapMsg->baseMsg.flags.flags.msgType);
    return MPLS_MSGTYPEERROR;
  }

  tempBuf += decodedSize;
  totalSize += decodedSize;

  if (bufSize - totalSize <= 0) {
    /* nothing left for decoding */
    PRINT_ERR("Lbl Mapping msg does not have anything beside base msg\n");
    return totalSize;
  }

  PRINT_OUT
    ("bufSize = %d,  totalSize = %d, lblMapMsg->baseMsg.msgLength = %d\n",
    bufSize, totalSize, lblMapMsg->baseMsg.msgLength);

  /* Have to check the baseMsg.msgLength to know when to finish.
   * We finsh when the totalSizeParam is >= to the base message length - the
   * message id length (4) 
   */

  stopLength = lblMapMsg->baseMsg.msgLength - MPLS_MSGIDFIXLEN;
  while (stopLength > totalSizeParam) {
    /*
     *  decode the tlv to check what's next
     */
    memset(&tlvTemp, 0, MPLS_TLVFIXLEN);
    decodedSize = Mpls_decodeLdpTlv(&tlvTemp, tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      /* something wrong */
      PRINT_ERR("Label Mapping msg decode failed for tlv\n");
      return MPLS_DEC_TLVERROR;
    }

    tempBuf += decodedSize;
    totalSize += decodedSize;
    totalSizeParam += decodedSize;

    switch (tlvTemp.flags.flags.tBit) {
      case MPLS_FEC_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpFecTlv(&(lblMapMsg->fecTlv),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding FEC tlv from LblMap msg\n");
            return MPLS_DEC_FECERROR;
          }
          PRINT_OUT("Decoded for FEC %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblMapMsg->fecTlvExists = 1;
          lblMapMsg->fecTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_GENLBL_TLVTYPE:
        {
          printf("PW_SIGNALING_FLAG: %d\n",PW_SIGNALING_FLAG);//testing
          if(PW_SIGNALING_FLAG==1)
             printf("***PW label***\n");
          else
             printf("***general label****\n");

          decodedSize = Mpls_decodeLdpGenLblTlv(&(lblMapMsg->genLblTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec GEN Lbl tlv from LblMap msg\n");
            return MPLS_DEC_GENLBLERROR;
          }
          PRINT_OUT("Decoded for Gen Lbl %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblMapMsg->genLblTlvExists = 1;
          lblMapMsg->genLblTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_ATMLBL_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpAtmLblTlv(&(lblMapMsg->atmLblTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec ATM Lbl tlv from LblMap msg\n");
            return MPLS_DEC_MAPATMERROR;
          }
          PRINT_OUT("Decoded for Atm Lbl %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblMapMsg->atmLblTlvExists = 1;
          lblMapMsg->atmLblTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_FRLBL_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpFrLblTlv(&(lblMapMsg->frLblTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec FR Lbl tlv from LblMap msg\n");
            return MPLS_DEC_FRLBLERROR;
          }
          PRINT_OUT("Decoded for Fr Lbl %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblMapMsg->frLblTlvExists = 1;
          lblMapMsg->frLblTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_HOPCOUNT_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpHopTlv(&(lblMapMsg->hopCountTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec HopCount tlv from LblMap msg\n");
            return MPLS_DEC_HOPCOUNTERROR;
          }
          PRINT_OUT("Decoded for HopCount %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblMapMsg->hopCountTlvExists = 1;
          lblMapMsg->hopCountTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_PATH_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpPathVectorTlv(&(lblMapMsg->pathVecTlv),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec Path Vec tlv from LblMap msg\n");
            return MPLS_DEC_PATHVECERROR;
          }
          PRINT_OUT("Decoded for PATH VECTOR %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblMapMsg->pathVecTlvExists = 1;
          lblMapMsg->pathVecTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_REQMSGID_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpLblMsgIdTlv(&(lblMapMsg->lblMsgIdTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec LblMsgId tlv from LblMap msg\n");
            return MPLS_DEC_LBLMSGIDERROR;
          }
          PRINT_OUT("Decoded for LblMsgId %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblMapMsg->lblMsgIdTlvExists = 1;
          lblMapMsg->lblMsgIdTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_TRAFFIC_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpTrafficTlv(&(lblMapMsg->trafficTlv),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec Traffic tlv from LblMap msg\n");
            return MPLS_DEC_TRAFFICERROR;
          }
          PRINT_OUT("Decoded for Traffic %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblMapMsg->trafficTlvExists = 1;
          lblMapMsg->trafficTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_LSPID_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpLspIdTlv(&(lblMapMsg->lspidTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec LSPID tlv from LblMap msg\n");
            return MPLS_DEC_LSPIDERROR;
          }
          PRINT_OUT("Decoded for lspid tlv %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblMapMsg->lspidTlvExists = 1;
          lblMapMsg->lspidTlv.baseTlv = tlvTemp;
          break;
        }
      default:
        {
          PRINT_ERR("Found wrong tlv type while decoding lbl map msg (%x)\n",
            tlvTemp.flags.flags.tBit);
          if (tlvTemp.flags.flags.uBit == 1) {
            /* ignore the Tlv and continue processing */
            tempBuf += tlvTemp.length;
            totalSize += tlvTemp.length;
            totalSizeParam += tlvTemp.length;
            break;
          } else {
            /* drop the message; return error */
            return MPLS_TLVTYPEERROR;
          }
        }
    }                           /* switch type */

  }                             /* while */

  PRINT_OUT("totalsize for Mpls_decodeLdpLblMapMsg is %d\n", totalSize);

  return totalSize;

}                               /* End: Mpls_decodeLdpLblMapMsg */

/* 
 * Encode for Retrun MessageId TLV 
 */

/*
 *  encode
 */
int Mpls_encodeLdpLblRetMsgIdTlv
  (mplsLdpLblRetMsgIdTlv_t * lblMsgIdTlv, u_char * buff, int bufSize) {
  /* 
   *  encode for tlv 
   */
  if (Mpls_encodeLdpTlv(&(lblMsgIdTlv->baseTlv), buff, MPLS_TLVFIXLEN) < 0) {
    return MPLS_ENC_TLVERROR;
  }

  return MPLS_TLVFIXLEN;

}                               /* End: Mpls_encodeLdpLblRetMsgIdTlv */

/*
 *  decode
 */
int Mpls_decodeLdpLblRetMsgIdTlv
  (mplsLdpLblRetMsgIdTlv_t * lblMsgIdTlv, u_char * buff, int bufSize) {
  /* this function does not need to do anything */
  return 0;
}                               /* End: Mpls_decodeLdpLblRetMsgIdTlv */

/* 
 * Encode for Label Request Message
 */

/*
 *  encode
 */
int Mpls_encodeLdpLblReqMsg
  (mplsLdpLblReqMsg_t * lblReqMsg, u_char * buff, int bufSize) {
  mplsLdpLblReqMsg_t lblReqMsgCopy;
  int encodedSize;
  u_int totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  /* check the length of the messageId + param */
  if ((int)(lblReqMsg->baseMsg.msgLength) + MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("failed to encode the lbl request msg: BUFFER TOO SMALL\n");
    return MPLS_ENC_BUFFTOOSMALL;
  }

  lblReqMsgCopy = *lblReqMsg;

  /*
   *  encode the base part of the pdu message
   */
  encodedSize = Mpls_encodeLdpBaseMsg(&(lblReqMsgCopy.baseMsg),
    tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_BASEMSGERROR;
  }
  PRINT_OUT("Encode BaseMsg for label request on %d bytes\n", encodedSize);
  tempBuf += encodedSize;
  totalSize += encodedSize;

  /*
   *  encode the tlv if any
   */
  if (lblReqMsgCopy.fecTlvExists) {
    encodedSize = Mpls_encodeLdpFecTlv(&(lblReqMsgCopy.fecTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_FECERROR;
    }
    PRINT_OUT("Encoded for FEC Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblReqMsgCopy.hopCountTlvExists) {
    encodedSize = Mpls_encodeLdpHopTlv(&(lblReqMsgCopy.hopCountTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_HOPCOUNTERROR;
    }
    PRINT_OUT("Encoded for Hop Count Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblReqMsgCopy.pathVecTlvExists) {
    encodedSize = Mpls_encodeLdpPathVectorTlv(&(lblReqMsgCopy.pathVecTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_PATHVECERROR;
    }
    PRINT_OUT("Encoded for Hop Count Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblReqMsgCopy.lblMsgIdTlvExists) {
    encodedSize = Mpls_encodeLdpLblRetMsgIdTlv(&(lblReqMsgCopy.lblMsgIdTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_LBLMSGIDERROR;
    }
    PRINT_OUT("Encoded for Hop Count Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblReqMsgCopy.erTlvExists) {
    encodedSize = Mpls_encodeLdpERTlv(&(lblReqMsgCopy.erTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_ERTLVERROR;
    }
    PRINT_OUT("Encoded for CR Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblReqMsgCopy.trafficTlvExists) {
    encodedSize = Mpls_encodeLdpTrafficTlv(&(lblReqMsgCopy.trafficTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_TRAFFICERROR;
    }
    PRINT_OUT("Encoded for Traffic Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblReqMsgCopy.lspidTlvExists) {
    encodedSize = Mpls_encodeLdpLspIdTlv(&(lblReqMsgCopy.lspidTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_LSPIDERROR;
    }
    PRINT_OUT("Encoded for LSPID Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblReqMsgCopy.pinningTlvExists) {
    encodedSize = Mpls_encodeLdpPinningTlv(&(lblReqMsgCopy.pinningTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_PINNINGERROR;
    }
    PRINT_OUT("Encoded for Pinning Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblReqMsgCopy.recClassTlvExists) {
    encodedSize = Mpls_encodeLdpResClsTlv(&(lblReqMsgCopy.resClassTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_RESCLSERROR;
    }
    PRINT_OUT("Encoded for Resource class Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblReqMsgCopy.preemptTlvExists) {
    encodedSize = Mpls_encodeLdpPreemptTlv(&(lblReqMsgCopy.preemptTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_PREEMPTERROR;
    }
    PRINT_OUT("Encoded for Preempt Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End: Mpls_encodeLdpLblReqMsg */

/*
 *  decode
 */
int Mpls_decodeLdpLblReqMsg
  (mplsLdpLblReqMsg_t * lblReqMsg, u_char * buff, int bufSize) {
  int decodedSize = 0;
  u_int totalSize = 0;
  u_int stopLength = 0;
  u_int totalSizeParam = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  mplsLdpTlv_t tlvTemp;

  /*
   *  decode the base part of the pdu message
   */
  memset(lblReqMsg, 0, sizeof(mplsLdpLblReqMsg_t));
  decodedSize = Mpls_decodeLdpBaseMsg(&(lblReqMsg->baseMsg), tempBuf, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for Lbl Request on %d bytes\n", decodedSize);

  if (lblReqMsg->baseMsg.flags.flags.msgType != MPLS_LBLREQ_MSGTYPE) {
    PRINT_ERR("Not the right message type; expected lbl req and got %x\n",
      lblReqMsg->baseMsg.flags.flags.msgType);
    return MPLS_MSGTYPEERROR;
  }

  tempBuf += decodedSize;
  totalSize += decodedSize;

  if (bufSize - totalSize <= 0) {
    /* nothing left for decoding */
    PRINT_ERR("Lbl Request msg does not have anything beside base msg\n");
    return totalSize;
  }

  PRINT_OUT
    ("bufSize = %d,  totalSize = %d, lblReqMsg->baseMsg.msgLength = %d\n",
    bufSize, totalSize, lblReqMsg->baseMsg.msgLength);

  /* Have to check the baseMsg.msgLength to know when to finish.
   * We finsh when the totalSizeParam is >= to the base message length - the
   * message id length (4) 
   */

  stopLength = lblReqMsg->baseMsg.msgLength - MPLS_MSGIDFIXLEN;
  while (stopLength > totalSizeParam) {
    /*
     *  decode the tlv to check what's next
     */
    memset(&tlvTemp, 0, MPLS_TLVFIXLEN);
    decodedSize = Mpls_decodeLdpTlv(&tlvTemp, tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      /* something wrong */
      PRINT_ERR("Label Request msg decode failed for tlv\n");
      return MPLS_DEC_TLVERROR;
    }

    tempBuf += decodedSize;
    totalSize += decodedSize;
    totalSizeParam += decodedSize;

    switch (tlvTemp.flags.flags.tBit) {
      case MPLS_FEC_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpFecTlv(&(lblReqMsg->fecTlv),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding FEC tlv from LblReq msg\n");
            return MPLS_DEC_FECERROR;
          }
          PRINT_OUT("Decoded for FEC %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblReqMsg->fecTlvExists = 1;
          lblReqMsg->fecTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_HOPCOUNT_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpHopTlv(&(lblReqMsg->hopCountTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec HopCount tlv from LblReq msg\n");
            return MPLS_DEC_HOPCOUNTERROR;
          }
          PRINT_OUT("Decoded for HopCount %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblReqMsg->hopCountTlvExists = 1;
          lblReqMsg->hopCountTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_PATH_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpPathVectorTlv(&(lblReqMsg->pathVecTlv),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec Path Vec tlv from LblReq msg\n");
            return MPLS_DEC_PATHVECERROR;
          }
          PRINT_OUT("Decoded for PATH VECTOR %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblReqMsg->pathVecTlvExists = 1;
          lblReqMsg->pathVecTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_LBLMSGID_TLVTYPE:
        {
          lblReqMsg->lblMsgIdTlvExists = 1;
          lblReqMsg->lblMsgIdTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_ER_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpERTlv(&(lblReqMsg->erTlv),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec CR tlv from LblReq msg\n");
            return MPLS_DEC_ERTLVERROR;
          }
          PRINT_OUT("Decoded for CR %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblReqMsg->erTlvExists = 1;
          lblReqMsg->erTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_TRAFFIC_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpTrafficTlv(&(lblReqMsg->trafficTlv),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec Traffic tlv from LblReq msg\n");
            return MPLS_DEC_TRAFFICERROR;
          }
          PRINT_OUT("Decoded for Traffic %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblReqMsg->trafficTlvExists = 1;
          lblReqMsg->trafficTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_LSPID_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpLspIdTlv(&(lblReqMsg->lspidTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec LSPID tlv from LblReq msg\n");
            return MPLS_DEC_LSPIDERROR;
          }
          PRINT_OUT("Decoded for lspid tlv %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblReqMsg->lspidTlvExists = 1;
          lblReqMsg->lspidTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_PINNING_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpPinningTlv(&(lblReqMsg->pinningTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec Pinning tlv from LblReq msg\n");
            return MPLS_DEC_PINNINGERROR;
          }
          PRINT_OUT("Decoded for pining tlv %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblReqMsg->pinningTlvExists = 1;
          lblReqMsg->pinningTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_RESCLASS_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpResClsTlv(&(lblReqMsg->resClassTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec ResClass tlv from LblReq msg\n");
            return MPLS_DEC_RESCLSERROR;
          }
          PRINT_OUT("Decoded for %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblReqMsg->recClassTlvExists = 1;
          lblReqMsg->resClassTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_PREEMPT_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpPreemptTlv(&(lblReqMsg->preemptTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec preempt tlv from LblReq msg\n");
            return MPLS_DEC_PREEMPTERROR;
          }
          PRINT_OUT("Decoded for preempt tlv %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblReqMsg->preemptTlvExists = 1;
          lblReqMsg->preemptTlv.baseTlv = tlvTemp;
          break;
        }
      default:
        {
          PRINT_ERR("Found wrong type while decoding lbl req msg (%x)\n",
            tlvTemp.flags.flags.tBit);
          if (tlvTemp.flags.flags.uBit == 1) {
            /* ignore the Tlv and continue processing */
            tempBuf += tlvTemp.length;
            totalSize += tlvTemp.length;
            totalSizeParam += tlvTemp.length;
            break;
          } else {
            /* drop the message; return error */
            return MPLS_TLVTYPEERROR;
          }
        }
    }                           /* switch type */

  }                             /* while */

  PRINT_OUT("totalsize for Mpls_decodeLdpLblReqMsg is %d\n", totalSize);
  return totalSize;

}                               /*End: Mpls_decodeLdpLblReqMsg */

/* 
 * Encode for Label Withdraw and Label Release Message
 */

/*
 *  encode
 */
int Mpls_encodeLdpLbl_W_R_Msg
  (mplsLdpLbl_W_R_Msg_t * lbl_W_R_Msg, u_char * buff, int bufSize) {
  mplsLdpLbl_W_R_Msg_t lbl_W_R_MsgCopy;
  int encodedSize;
  u_int totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  /* check the length of the messageId + param */
  if ((int)(lbl_W_R_Msg->baseMsg.msgLength) + MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("failed to encode the lbl mapping msg: BUFFER TOO SMALL\n");
    return MPLS_ENC_BUFFTOOSMALL;
  }

  lbl_W_R_MsgCopy = *lbl_W_R_Msg;

  /*
   *  encode the base part of the pdu message
   */
  encodedSize = Mpls_encodeLdpBaseMsg(&(lbl_W_R_MsgCopy.baseMsg),
    tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_BASEMSGERROR;
  }
  PRINT_OUT("Encode BaseMsg for label withdraw on %d bytes\n", encodedSize);
  tempBuf += encodedSize;
  totalSize += encodedSize;

  /*
   *  encode the tlv if any
   */
  if (lbl_W_R_MsgCopy.fecTlvExists) {
    encodedSize = Mpls_encodeLdpFecTlv(&(lbl_W_R_MsgCopy.fecTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_FECERROR;
    }
    PRINT_OUT("Encoded for FEC Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  if (lbl_W_R_MsgCopy.genLblTlvExists) {
    encodedSize = Mpls_encodeLdpGenLblTlv(&(lbl_W_R_MsgCopy.genLblTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_GENLBLERROR;
    }
    PRINT_OUT("Encoded for Generic Label Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lbl_W_R_MsgCopy.atmLblTlvExists) {
    encodedSize = Mpls_encodeLdpAtmLblTlv(&(lbl_W_R_MsgCopy.atmLblTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_MAPATMERROR;
    }
    PRINT_OUT("Encoded for Atm Label Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lbl_W_R_MsgCopy.frLblTlvExists) {
    encodedSize = Mpls_encodeLdpFrLblTlv(&(lbl_W_R_MsgCopy.frLblTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_FRLBLERROR;
    }
    PRINT_OUT("Encoded for Fr Label Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lbl_W_R_MsgCopy.lspidTlvExists) {
    encodedSize = Mpls_encodeLdpLspIdTlv(&(lbl_W_R_MsgCopy.lspidTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_LSPIDERROR;
    }
    PRINT_OUT("Encoded for LSPID Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End: Mpls_encodeLdpLbl_W_R_Msg */

/*
 *  decode
 */
int Mpls_decodeLdpLbl_W_R_Msg
  (mplsLdpLbl_W_R_Msg_t * lbl_W_R_Msg, u_char * buff, int bufSize) {
  int decodedSize;
  u_int totalSize = 0;
  u_int stopLength = 0;
  u_int totalSizeParam = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  mplsLdpTlv_t tlvTemp;

  /*
   *  decode the base part of the pdu message
   */
  memset(lbl_W_R_Msg, 0, sizeof(mplsLdpLbl_W_R_Msg_t));
  decodedSize = Mpls_decodeLdpBaseMsg(&(lbl_W_R_Msg->baseMsg),
    tempBuf, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for Lbl Withdraw on %d bytes\n", decodedSize);

  if ((lbl_W_R_Msg->baseMsg.flags.flags.msgType != MPLS_LBLWITH_MSGTYPE) &&
    (lbl_W_R_Msg->baseMsg.flags.flags.msgType != MPLS_LBLREL_MSGTYPE)) {
    PRINT_ERR("Not the right message type; expected lbl W_R and got %x\n",
      lbl_W_R_Msg->baseMsg.flags.flags.msgType);
    return MPLS_MSGTYPEERROR;
  }

  tempBuf += decodedSize;
  totalSize += decodedSize;

  if (bufSize - totalSize <= 0) {
    /* nothing left for decoding */
    PRINT_ERR("Lbl Withdraw msg does not have anything beside base msg\n");
    return totalSize;
  }

  PRINT_OUT
    ("bufSize = %d,  totalSize = %d, lbl_W_R_Msg->baseMsg.msgLength = %d\n",
    bufSize, totalSize, lbl_W_R_Msg->baseMsg.msgLength);

  /* Have to check the baseMsg.msgLength to know when to finish.
   * We finsh when the totalSizeParam is >= to the base message length - the
   * message id length (4) 
   */

  stopLength = lbl_W_R_Msg->baseMsg.msgLength - MPLS_MSGIDFIXLEN;
  while (stopLength > totalSizeParam) {
    /*
     *  decode the tlv to check what's next
     */
    memset(&tlvTemp, 0, MPLS_TLVFIXLEN);
    decodedSize = Mpls_decodeLdpTlv(&tlvTemp, tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      /* something wrong */
      PRINT_ERR("Label Mapping msg decode failed for tlv\n");
      return MPLS_DEC_TLVERROR;
    }

    tempBuf += decodedSize;
    totalSize += decodedSize;
    totalSizeParam += decodedSize;

    switch (tlvTemp.flags.flags.tBit) {
      case MPLS_FEC_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpFecTlv(&(lbl_W_R_Msg->fecTlv),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding FEC tlv from LblWithdr msg\n");
            return MPLS_DEC_FECERROR;
          }
          PRINT_OUT("Decoded for FEC %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lbl_W_R_Msg->fecTlvExists = 1;
          lbl_W_R_Msg->fecTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_GENLBL_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpGenLblTlv(&(lbl_W_R_Msg->genLblTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec GEN Lbl tlv from LblWithdr msg\n");
            return MPLS_DEC_GENLBLERROR;
          }
          PRINT_OUT("Decoded for Gen Lbl %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lbl_W_R_Msg->genLblTlvExists = 1;
          lbl_W_R_Msg->genLblTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_ATMLBL_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpAtmLblTlv(&(lbl_W_R_Msg->atmLblTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec ATM Lbl tlv from LblWithdr msg\n");
            return MPLS_DEC_MAPATMERROR;
          }
          PRINT_OUT("Decoded for Atm Lbl %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lbl_W_R_Msg->atmLblTlvExists = 1;
          lbl_W_R_Msg->atmLblTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_FRLBL_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpFrLblTlv(&(lbl_W_R_Msg->frLblTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec FR Lbl tlv from LblWithdr msg\n");
            return MPLS_DEC_FRLBLERROR;
          }
          PRINT_OUT("Decoded for Fr Lbl %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lbl_W_R_Msg->frLblTlvExists = 1;
          lbl_W_R_Msg->frLblTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_LSPID_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpLspIdTlv(&(lbl_W_R_Msg->lspidTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec LSPID tlv from LblW_R msg\n");
            return MPLS_DEC_LSPIDERROR;
          }
          PRINT_OUT("Decoded for lspid tlv %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lbl_W_R_Msg->lspidTlvExists = 1;
          lbl_W_R_Msg->lspidTlv.baseTlv = tlvTemp;
          break;
        }
      default:
        {
          PRINT_ERR("Found wrong tlv type while decoding lbl withdr msg (%x)\n",
            tlvTemp.flags.flags.tBit);
          if (tlvTemp.flags.flags.uBit == 1) {
            /* ignore the Tlv and continue processing */
            tempBuf += tlvTemp.length;
            totalSize += tlvTemp.length;
            totalSizeParam += tlvTemp.length;
            break;
          } else {
            /* drop the message; return error */
            return MPLS_TLVTYPEERROR;
          }
        }
    }                           /* switch type */

  }                             /* while */

  PRINT_OUT("totalsize for Mpls_decodeLdpLblWithdrawMsgIdTlv is %d\n",
    totalSize);

  return totalSize;

}                               /* End: Mpls_decodeLdpLbl_W_R_Msg */

/* 
 * Encode for CR Tlv 
 */

/*
 *  encode
 */
int Mpls_encodeLdpERTlv(mplsLdpErTlv_t * erTlv, u_char * buff, int bufSize)
{
  int encodedSize = 0;
  u_int totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_int i;

  if (MPLS_TLVFIXLEN + (int)(erTlv->baseTlv.length) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(erTlv->baseTlv), tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;
  totalSize += encodedSize;

  if (erTlv->numberErHops > MPLS_MAX_ER_HOPS) {
    PRINT_ERR("MPLS_MAX_ER_HOPS is too small. Increase it if nec\n");
    return MPLS_ER_HOPSNUMERROR;
  }

  /* 
   *  encode for ER hops 
   */
  for (i = 0; i < erTlv->numberErHops; i++) {
    encodedSize = Mpls_encodeLdpErHop(&(erTlv->erHopArray[i]),
      tempBuf, bufSize - totalSize, erTlv->erHopTypes[i]);
    if (encodedSize < 0) {
      return MPLS_ENC_ERHOPERROR;
    }
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End: Mpls_encodeLdpERTlv */

/*
 *  decode
 */
int Mpls_decodeLdpERTlv
  (mplsLdpErTlv_t * erTlv, u_char * buff, int bufSize, u_short tlvLength) {
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_char *erTlvPtr;
  u_int i = 0;
  int decodedSize = 0;
  u_int erHopSize = 0;          /* used to compute the sum of

                                   all er hop elements + flags */
  u_short type;                 /* filled in by Mpls_decodeLdpErHop

                                   with the type of the ER hop 
                                   decoded */

  if ((int)tlvLength > bufSize) {
    /* not enough data for Fec elements tlv */
    PRINT_ERR("failed decoding CR tlv \n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  erTlvPtr = (u_char *) erTlv;
  erTlvPtr += MPLS_TLVFIXLEN;   /* we want to point to the flags since the
                                   tlv was decoded before we reach here */

  while (tlvLength > erHopSize) {
    if (erTlv->numberErHops > (u_short) (MPLS_MAX_ER_HOPS - 1)) {
      PRINT_ERR("MPLS_MAX_ER_HOPS is too small. Increase it if nec\n");
      return MPLS_ER_HOPSNUMERROR;
    }

    decodedSize = Mpls_decodeLdpErHop(&(erTlv->erHopArray[i]),
      tempBuf, bufSize - erHopSize, &type);
    if (decodedSize < 0) {
      return MPLS_DEC_ERHOPERROR;
    }

    erTlv->erHopTypes[i] = type;
    erTlv->numberErHops++;
    i++;

    tempBuf += decodedSize;
    erHopSize += decodedSize;

  }                             /* end while */

  return erHopSize;

}                               /* End: Mpls_decodeLdpERTlv */

/* 
 * Encode for ER Hop 
 */

/*
 *  encode
 */
int Mpls_encodeLdpErHop
  (mplsLdpErHop_t * erHop, u_char * buff, int bufSize, u_short type) {
  int encodedSize = 0;
  u_char *tempBuff = buff;
  u_char *startPtr;

  switch (type) {
    case MPLS_ERHOP_IPV4_TLVTYPE:
      {
        if (MPLS_ERHOP_IPV4_FIXLEN + MPLS_TLVFIXLEN > bufSize) {
          return MPLS_ENC_BUFFTOOSMALL;
        }

        /* check how much is the preLen; should be between 0-32 */
        if (erHop->erIpv4.flags.flags.preLen > 32) {
          return MPLS_IPV4LENGTHERROR;
        }

        encodedSize = Mpls_encodeLdpTlv(&(erHop->erIpv4.baseTlv),
          tempBuff, bufSize);
        if (encodedSize < 0) {
          return MPLS_ENC_TLVERROR;
        }
        tempBuff += encodedSize;
        startPtr = (u_char *) & (erHop->erIpv4);
        startPtr += encodedSize;

        erHop->erIpv4.flags.flags.res = 0;
        erHop->erIpv4.flags.mark = htonl(erHop->erIpv4.flags.mark);
        erHop->erIpv4.address = htonl(erHop->erIpv4.address);

        MEM_COPY(tempBuff, startPtr, MPLS_ERHOP_IPV4_FIXLEN);
        encodedSize += MPLS_ERHOP_IPV4_FIXLEN;
        break;
      }
    case MPLS_ERHOP_IPV6_TLVTYPE:
      {
        if (MPLS_ERHOP_IPV6_FIXLEN + MPLS_TLVFIXLEN > bufSize) {
          return MPLS_ENC_BUFFTOOSMALL;
        }
        encodedSize = Mpls_encodeLdpTlv(&(erHop->erIpv6.baseTlv),
          tempBuff, bufSize);
        if (encodedSize < 0) {
          return MPLS_ENC_TLVERROR;
        }
        tempBuff += encodedSize;
        startPtr = (u_char *) & (erHop->erIpv6);
        startPtr += encodedSize;

        erHop->erIpv6.flags.flags.res = 0;
        erHop->erIpv6.flags.mark = htonl(erHop->erIpv6.flags.mark);

        MEM_COPY(tempBuff, startPtr, MPLS_ERHOP_IPV6_FIXLEN);

        encodedSize += MPLS_ERHOP_IPV6_FIXLEN;
        break;
      }
    case MPLS_ERHOP_AS_TLVTYPE:
      {
        if (MPLS_ERHOP_AS_FIXLEN + MPLS_TLVFIXLEN > bufSize) {
          return MPLS_ENC_BUFFTOOSMALL;
        }
        encodedSize =
          Mpls_encodeLdpTlv(&(erHop->erAs.baseTlv), tempBuff, bufSize);
        if (encodedSize < 0) {
          return MPLS_ENC_TLVERROR;
        }
        tempBuff += encodedSize;
        startPtr = (u_char *) & (erHop->erAs);
        startPtr += encodedSize;

        erHop->erAs.flags.flags.res = 0;
        erHop->erAs.flags.mark = htons(erHop->erAs.flags.mark);
        erHop->erAs.asNumber = htons(erHop->erAs.asNumber);

        MEM_COPY(tempBuff, startPtr, MPLS_ERHOP_AS_FIXLEN);

        encodedSize += MPLS_ERHOP_AS_FIXLEN;
        break;
      }
    case MPLS_ERHOP_LSPID_TLVTYPE:
      {
        if (MPLS_ERHOP_LSPID_FIXLEN + MPLS_TLVFIXLEN > bufSize) {
          return MPLS_ENC_BUFFTOOSMALL;
        }
        encodedSize = Mpls_encodeLdpTlv(&(erHop->erLspId.baseTlv),
          tempBuff, bufSize);
        if (encodedSize < 0) {
          return MPLS_ENC_TLVERROR;
        }
        tempBuff += encodedSize;
        startPtr = (u_char *) & (erHop->erLspId);
        startPtr += encodedSize;

        erHop->erLspId.flags.flags.res = 0;
        erHop->erLspId.flags.mark = htons(erHop->erLspId.flags.mark);
        erHop->erLspId.lspid = htons(erHop->erLspId.lspid);
        erHop->erLspId.routerId = htonl(erHop->erLspId.routerId);

        MEM_COPY(tempBuff, startPtr, MPLS_ERHOP_LSPID_FIXLEN);

        encodedSize += MPLS_ERHOP_LSPID_FIXLEN;
        break;
      }
    default:
      {
        PRINT_ERR("Found wrong ER hop type while encoding FEC elem (%d)\n",
          type);
        return MPLS_ENC_ERHOPERROR;
        break;
      }
  }                             /* end: switch */

  return encodedSize;

}                               /* End: Mpls_encodeLdpErHop */

/*
 *  decode
 */
int Mpls_decodeLdpErHop
  (mplsLdpErHop_t * erHop, u_char * buff, int bufSize, u_short * type) {
  int decodedSize = 0;
  u_char *tempBuf = buff;
  u_char *startPtr;
  mplsLdpTlv_t tlvTemp;

  /*
   *  decode the tlv to check what is the type of the ER hop
   */
  decodedSize = Mpls_decodeLdpTlv(&tlvTemp, tempBuf, bufSize);
  if (decodedSize < 0) {
    /* something wrong */
    PRINT_ERR("ErHop decode failed for tlv\n");
    return MPLS_DEC_TLVERROR;
  }
  tempBuf += decodedSize;

  switch (tlvTemp.flags.flags.tBit) {
    case MPLS_ERHOP_IPV4_TLVTYPE:
      {
        if (MPLS_ERHOP_IPV4_FIXLEN > bufSize - MPLS_TLVFIXLEN) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        startPtr = (u_char *) & (erHop->erIpv4);
        startPtr += decodedSize; /* skip the tlv */

        MEM_COPY(startPtr, tempBuf, MPLS_ERHOP_IPV4_FIXLEN);
        erHop->erIpv4.flags.mark = ntohl(erHop->erIpv4.flags.mark);
        erHop->erIpv4.address = ntohl(erHop->erIpv4.address);
        erHop->erIpv4.baseTlv = tlvTemp;

        /* check how much is the preLen; should be between 0-32 */
        if (erHop->erIpv4.flags.flags.preLen > 32) {
          return MPLS_IPV4LENGTHERROR;
        }

        decodedSize += MPLS_ERHOP_IPV4_FIXLEN;
        break;
      }
    case MPLS_ERHOP_IPV6_TLVTYPE:
      {
        if (MPLS_ERHOP_IPV6_FIXLEN > bufSize - MPLS_TLVFIXLEN) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        startPtr = (u_char *) & (erHop->erIpv6);
        startPtr += decodedSize; /* skip the tlv */

        MEM_COPY(startPtr, tempBuf, MPLS_ERHOP_IPV6_FIXLEN);
        erHop->erIpv6.flags.mark = ntohl(erHop->erIpv6.flags.mark);
        erHop->erIpv6.baseTlv = tlvTemp;

        decodedSize += MPLS_ERHOP_IPV6_FIXLEN;
        break;
      }
    case MPLS_ERHOP_AS_TLVTYPE:
      {
        if (MPLS_ERHOP_AS_FIXLEN > bufSize - MPLS_TLVFIXLEN) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        startPtr = (u_char *) & (erHop->erAs);
        startPtr += decodedSize; /* skip the tlv */

        MEM_COPY(startPtr, tempBuf, MPLS_ERHOP_AS_FIXLEN);
        erHop->erAs.flags.mark = ntohs(erHop->erAs.flags.mark);
        erHop->erAs.asNumber = ntohs(erHop->erAs.asNumber);
        erHop->erAs.baseTlv = tlvTemp;

        decodedSize += MPLS_ERHOP_AS_FIXLEN;
        break;
      }
    case MPLS_ERHOP_LSPID_TLVTYPE:
      {
        if (MPLS_ERHOP_LSPID_FIXLEN > bufSize - MPLS_TLVFIXLEN) {
          return MPLS_DEC_BUFFTOOSMALL;
        }
        startPtr = (u_char *) & (erHop->erLspId);
        startPtr += decodedSize; /* skip the tlv */

        MEM_COPY(startPtr, tempBuf, MPLS_ERHOP_LSPID_FIXLEN);
        erHop->erLspId.flags.mark = ntohs(erHop->erLspId.flags.mark);
        erHop->erLspId.lspid = ntohs(erHop->erLspId.lspid);
        erHop->erLspId.routerId = ntohl(erHop->erLspId.routerId);
        erHop->erLspId.baseTlv = tlvTemp;

        decodedSize += MPLS_ERHOP_LSPID_FIXLEN;
        break;
      }
    default:
      {
        PRINT_ERR("Found wrong ER hop type while decoding ER (%d)\n", *type);
        return MPLS_DEC_ERHOPERROR;
        break;
      }
  }                             /* end: switch */

  *type = tlvTemp.flags.flags.tBit;
  return decodedSize;

}                               /* End: Mpls_decodeLdpErHop */

/* 
 * Encode for Traffic Tlv 
 */

/*
 *  encode
 */
int Mpls_encodeLdpTrafficTlv
  (mplsLdpTrafficTlv_t * trafficTlv, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_char *trafficTlvPtr;
  u_short tempLength;           /* to store the tlv length for

                                   later use */

  if (MPLS_TLVFIXLEN + (int)(trafficTlv->baseTlv.length) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  tempLength = trafficTlv->baseTlv.length;
  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(trafficTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;
  trafficTlvPtr = (u_char *) trafficTlv;
  trafficTlvPtr += encodedSize;

  /*
   *   encode Traffic flags + Frequency + Reserved + Weight
   */
  encodedSize = sizeof(u_char) * 4;
  MEM_COPY(tempBuf, trafficTlvPtr, encodedSize);
  tempBuf += encodedSize;
  trafficTlvPtr += encodedSize;

  /*
   *   encode for Traffic parameters 
   */
  if ((MPLS_TRAFFICPARAMLENGTH != sizeof(float)) ||
    (sizeof(float) != sizeof(u_int))) {
    PRINT_ERR("There is not compatibility for float type (%d)\n",

      (int)sizeof(float));
    return MPLS_FLOATTYPEERROR;
  }

  trafficTlv->pdr.mark = htonl(trafficTlv->pdr.mark);
  trafficTlv->pbs.mark = htonl(trafficTlv->pbs.mark);
  trafficTlv->cdr.mark = htonl(trafficTlv->cdr.mark);
  trafficTlv->cbs.mark = htonl(trafficTlv->cbs.mark);
  trafficTlv->ebs.mark = htonl(trafficTlv->ebs.mark);

  MEM_COPY(tempBuf, trafficTlvPtr, MPLS_TRAFFICPARAMLENGTH * 5);

  return (MPLS_TLVFIXLEN + tempLength);

}                               /* End: Mpls_encodeLdpTrafficTlv */

/*
 *  decode
 */
int Mpls_decodeLdpTrafficTlv
  (mplsLdpTrafficTlv_t * trafficTlv,
  u_char * buff, int bufSize, u_short tlvLength) {
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  int decodedSize = 0;
  u_char *trafficTlvPtr;

  if ((int)tlvLength > bufSize) {
    /* not enough data for Fec elements tlv */
    PRINT_ERR("failed decoding Traffic tlv \n");
    return MPLS_DEC_BUFFTOOSMALL;
  }
  trafficTlvPtr = (u_char *) trafficTlv;
  trafficTlvPtr += MPLS_TLVFIXLEN;

  /*
   *   decode Traffic flags + Frequency + Reserved + Weight
   */
  decodedSize = sizeof(u_char) * 4;
  MEM_COPY(trafficTlvPtr, tempBuf, decodedSize);
  tempBuf += decodedSize;
  trafficTlvPtr += decodedSize;

  /* 
   * decode the traffic parameters
   */
  if (MPLS_TRAFFICPARAMLENGTH != sizeof(float)) {
    PRINT_ERR("There is not compatibility for float type (%d)\n", decodedSize);
    return MPLS_FLOATTYPEERROR;
  }
  MEM_COPY(trafficTlvPtr, tempBuf, MPLS_TRAFFICPARAMLENGTH * 5);

  trafficTlv->pdr.mark = ntohl(trafficTlv->pdr.mark);
  trafficTlv->pbs.mark = ntohl(trafficTlv->pbs.mark);
  trafficTlv->cdr.mark = ntohl(trafficTlv->cdr.mark);
  trafficTlv->cbs.mark = ntohl(trafficTlv->cbs.mark);
  trafficTlv->ebs.mark = ntohl(trafficTlv->ebs.mark);

  return tlvLength;

}                               /* End: Mpls_decodeLdpTrafficTlv */

/* 
 * Encode for Preempt Tlv 
 */

/*
 *  encode
 */
int Mpls_encodeLdpPreemptTlv
  (mplsLdpPreemptTlv_t * preemptTlv, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_char *preemptTlvPtr;

  if (MPLS_TLVFIXLEN + MPLS_PREEMPTTLV_FIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(preemptTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  preemptTlv->res = 0;
  preemptTlvPtr = (u_char *) preemptTlv;
  preemptTlvPtr += encodedSize;

  MEM_COPY(tempBuf, preemptTlvPtr, MPLS_PREEMPTTLV_FIXLEN);

  return (MPLS_TLVFIXLEN + MPLS_PREEMPTTLV_FIXLEN);

}                               /* End: Mpls_encodeLdpPreemptTlv */

/*
 *  decode
 */
int Mpls_decodeLdpPreemptTlv
  (mplsLdpPreemptTlv_t * preemptTlv, u_char * buff, int bufSize) {
  u_char *preemptTlvPtr;

  if (MPLS_PREEMPTTLV_FIXLEN > bufSize) {
    PRINT_ERR("failed decoding preempt tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }
  preemptTlvPtr = (u_char *) preemptTlv;
  preemptTlvPtr += MPLS_TLVFIXLEN;

  MEM_COPY(preemptTlvPtr, buff, MPLS_PREEMPTTLV_FIXLEN);

  return MPLS_PREEMPTTLV_FIXLEN;

}                               /* End: Mpls_decodeLdpPreemptTlv */

/* 
 * Encode for LSPID Tlv 
 */

/*
 *  encode
 */
int Mpls_encodeLdpLspIdTlv
  (mplsLdpLspIdTlv_t * lspIdTlv, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  u_char *lspIdTlvPtr;

  if (MPLS_TLVFIXLEN + MPLS_LSPIDTLV_FIXLEN > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(lspIdTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  lspIdTlvPtr = (u_char *) lspIdTlv;
  lspIdTlvPtr += encodedSize;

  lspIdTlv->res = 0;
  lspIdTlv->localCrlspId = htons(lspIdTlv->localCrlspId);
  lspIdTlv->routerId = htonl(lspIdTlv->routerId);

  MEM_COPY(tempBuf, lspIdTlvPtr, MPLS_LSPIDTLV_FIXLEN);

  return (MPLS_TLVFIXLEN + MPLS_LSPIDTLV_FIXLEN);

}                               /* End: Mpls_encodeLdpLspIdTlv */

/*
 *  decode
 */
int Mpls_decodeLdpLspIdTlv
  (mplsLdpLspIdTlv_t * lspIdTlv, u_char * buff, int bufSize) {
  u_char *lspIdTlvPtr;

  if (MPLS_PREEMPTTLV_FIXLEN > bufSize) {
    PRINT_ERR("failed decoding LspId\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }
  lspIdTlvPtr = (u_char *) lspIdTlv;
  lspIdTlvPtr += MPLS_TLVFIXLEN;

  MEM_COPY(lspIdTlvPtr, buff, MPLS_LSPIDTLV_FIXLEN);

  lspIdTlv->localCrlspId = ntohs(lspIdTlv->localCrlspId);
  lspIdTlv->routerId = ntohl(lspIdTlv->routerId);

  return MPLS_LSPIDTLV_FIXLEN;

}                               /* End:  Mpls_decodeLdpLspIdTlv */

/* 
 * Encode for Resource Class Tlv 
 */

/*
 *  encode
 */
int Mpls_encodeLdpResClsTlv
  (mplsLdpResClsTlv_t * resClsTlv, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_TLVFIXLEN + (int)sizeof(u_int) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(resClsTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  resClsTlv->rsCls = htonl(resClsTlv->rsCls);

  MEM_COPY(tempBuf, (u_char *) & (resClsTlv->rsCls), sizeof(u_int));

  return (MPLS_TLVFIXLEN + sizeof(u_int));

}                               /* End: Mpls_encodeLdpResClsTlv */

/*
 *  decode
 */
int Mpls_decodeLdpResClsTlv
  (mplsLdpResClsTlv_t * resClsTlv, u_char * buff, int bufSize) {
  if ((int)sizeof(u_int) > bufSize) {
    PRINT_ERR("failed decoding resClass tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  MEM_COPY((u_char *) & (resClsTlv->rsCls), buff, sizeof(u_int));
  resClsTlv->rsCls = ntohl(resClsTlv->rsCls);

  return sizeof(u_int);

}                               /* End: Mpls_decodeLdpResClsTlv */

/* 
 * Encode for Route Pinning Tlv 
 */

/*
 *  encode
 */
int Mpls_encodeLdpPinningTlv
  (mplsLdpPinningTlv_t * pinningTlv, u_char * buff, int bufSize) {
  int encodedSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  if (MPLS_TLVFIXLEN + (int)sizeof(u_int) > bufSize) {
    /* not enough room */
    return MPLS_ENC_BUFFTOOSMALL;
  }

  /* 
   *  encode for tlv 
   */
  encodedSize = Mpls_encodeLdpTlv(&(pinningTlv->baseTlv),
    tempBuf, MPLS_TLVFIXLEN);
  if (encodedSize < 0) {
    return MPLS_ENC_TLVERROR;
  }
  tempBuf += encodedSize;

  pinningTlv->flags.flags.res = 0;
  pinningTlv->flags.mark = htonl(pinningTlv->flags.mark);

  MEM_COPY(tempBuf, (u_char *) & (pinningTlv->flags.mark), sizeof(u_int));

  return (MPLS_TLVFIXLEN + sizeof(u_int));

}                               /* End: Mpls_encodeLdpPinningTlv */

/*
 *  decode
 */
int Mpls_decodeLdpPinningTlv
  (mplsLdpPinningTlv_t * pinningTlv, u_char * buff, int bufSize) {
  if ((int)sizeof(u_int) > bufSize) {
    PRINT_ERR("failed decoding route pinning tlv\n");
    return MPLS_DEC_BUFFTOOSMALL;
  }

  MEM_COPY((u_char *) & (pinningTlv->flags.mark), buff, sizeof(u_int));
  pinningTlv->flags.mark = ntohl(pinningTlv->flags.mark);

  return sizeof(u_int);

}                               /* End: Mpls_decodeLdpPinningTlv */

/* 
 * Label Abort Request Message
 */

/*
 *  encode
 */
int Mpls_encodeLdpLblAbortMsg
  (mplsLdpLblAbortMsg_t * lblAbortMsg, u_char * buff, int bufSize) {
  mplsLdpLblAbortMsg_t lblAbortMsgCopy;
  int encodedSize = 0;
  u_int totalSize = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */

  /* check the length of the messageId + param */
  if ((int)(lblAbortMsg->baseMsg.msgLength) + MPLS_TLVFIXLEN > bufSize) {
    PRINT_ERR("failed to encode the lbl abort request msg: BUFFER TOO SMALL\n");
    return MPLS_ENC_BUFFTOOSMALL;
  }

  lblAbortMsgCopy = *lblAbortMsg;

  /*
   *  encode the base part of the pdu message
   */
  encodedSize = Mpls_encodeLdpBaseMsg(&(lblAbortMsgCopy.baseMsg),
    tempBuf, bufSize);
  if (encodedSize < 0) {
    return MPLS_ENC_BASEMSGERROR;
  }
  PRINT_OUT("Encode BaseMsg for label abort request msg on %d bytes\n",
    encodedSize);
  tempBuf += encodedSize;
  totalSize += encodedSize;

  /*
   *  encode the tlv if any
   */
  if (lblAbortMsgCopy.fecTlvExists) {
    encodedSize = Mpls_encodeLdpFecTlv(&(lblAbortMsgCopy.fecTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_FECERROR;
    }
    PRINT_OUT("Encoded for FEC Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }
  if (lblAbortMsgCopy.lblMsgIdTlvExists) {
    encodedSize = Mpls_encodeLdpLblMsgIdTlv(&(lblAbortMsgCopy.lblMsgIdTlv),
      tempBuf, bufSize - totalSize);
    if (encodedSize < 0) {
      return MPLS_ENC_LBLMSGIDERROR;
    }
    PRINT_OUT("Encoded for lbl request msg id Tlv %d bytes\n", encodedSize);
    tempBuf += encodedSize;
    totalSize += encodedSize;
  }

  return totalSize;

}                               /* End: Mpls_encodeLdpLblAbortMsg */

/*
 *  decode
 */
int Mpls_decodeLdpLblAbortMsg
  (mplsLdpLblAbortMsg_t * lblAbortMsg, u_char * buff, int bufSize) {
  int decodedSize = 0;
  u_int totalSize = 0;
  u_int stopLength = 0;
  u_int totalSizeParam = 0;
  u_char *tempBuf = buff;       /* no change for the buff ptr */
  mplsLdpTlv_t tlvTemp;

  /*
   *  decode the base part of the pdu message
   */
  memset(lblAbortMsg, 0, sizeof(mplsLdpLblAbortMsg_t));
  decodedSize = Mpls_decodeLdpBaseMsg(&(lblAbortMsg->baseMsg),
    tempBuf, bufSize);
  if (decodedSize < 0) {
    return MPLS_DEC_BASEMSGERROR;
  }
  PRINT_OUT("Decode BaseMsg for Lbl Abort Request Msg on %d bytes\n",
    decodedSize);

  if (lblAbortMsg->baseMsg.flags.flags.msgType != MPLS_LBLABORT_MSGTYPE) {
    PRINT_ERR("Not the right message type; expected lbl abort and got %x\n",
      lblAbortMsg->baseMsg.flags.flags.msgType);
    return MPLS_MSGTYPEERROR;
  }

  tempBuf += decodedSize;
  totalSize += decodedSize;

  if (bufSize - totalSize <= 0) {
    /* nothing left for decoding */
    PRINT_ERR("Lbl Abort msg does not have anything beside base msg\n");
    return totalSize;
  }

  PRINT_OUT
    ("bufSize = %d,  totalSize = %d, lblAbortMsg->baseMsg.msgLength = %d\n",
    bufSize, totalSize, lblAbortMsg->baseMsg.msgLength);

  /* Have to check the baseMsg.msgLength to know when to finish.
   * We finsh when the totalSizeParam is >= to the base message length - the
   * message id length (4) 
   */

  stopLength = lblAbortMsg->baseMsg.msgLength - MPLS_MSGIDFIXLEN;
  while (stopLength > totalSizeParam) {
    /*
     *  decode the tlv to check what's next
     */
    memset(&tlvTemp, 0, MPLS_TLVFIXLEN);
    decodedSize = Mpls_decodeLdpTlv(&tlvTemp, tempBuf, bufSize - totalSize);
    if (decodedSize < 0) {
      /* something wrong */
      PRINT_ERR("Label Abort msg decode failed for tlv\n");
      return MPLS_DEC_TLVERROR;
    }

    tempBuf += decodedSize;
    totalSize += decodedSize;
    totalSizeParam += decodedSize;

    switch (tlvTemp.flags.flags.tBit) {
      case MPLS_FEC_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpFecTlv(&(lblAbortMsg->fecTlv),
            tempBuf, bufSize - totalSize, tlvTemp.length);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when decoding FEC tlv from LblAbort msg\n");
            return MPLS_DEC_FECERROR;
          }
          PRINT_OUT("Decoded for FEC %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblAbortMsg->fecTlvExists = 1;
          lblAbortMsg->fecTlv.baseTlv = tlvTemp;
          break;
        }
      case MPLS_REQMSGID_TLVTYPE:
        {
          decodedSize = Mpls_decodeLdpLblMsgIdTlv(&(lblAbortMsg->lblMsgIdTlv),
            tempBuf, bufSize - totalSize);
          if (decodedSize < 0) {
            PRINT_ERR("Failure when dec LblMsgId tlv from LblAbort msg\n");
            return MPLS_DEC_LBLMSGIDERROR;
          }
          PRINT_OUT("Decoded for LblMsgId %d bytes\n", decodedSize);
          tempBuf += decodedSize;
          totalSize += decodedSize;
          totalSizeParam += decodedSize;

          lblAbortMsg->lblMsgIdTlvExists = 1;
          lblAbortMsg->lblMsgIdTlv.baseTlv = tlvTemp;
          break;
        }
      default:
        {
          PRINT_ERR("Found wrong tlv type while decoding lbl abort msg (%x)\n",
            tlvTemp.flags.flags.tBit);
          if (tlvTemp.flags.flags.uBit == 1) {
            /* ignore the Tlv and continue processing */
            tempBuf += tlvTemp.length;
            totalSize += tlvTemp.length;
            totalSizeParam += tlvTemp.length;
            break;
          } else {
            /* drop the message; return error */
            return MPLS_TLVTYPEERROR;
          }
        }
    }                           /* switch type */

  }                             /* while */

  PRINT_OUT("totalsize for Mpls_decodeLdpLblAbortMsg is %d\n", totalSize);

  return totalSize;

}                               /* End: Mpls_decodeLdpLblAbortMsg */

/*
 *   DEBUG functions 
 */
void printTlv(mpls_instance_handle handle, mplsLdpTlv_t * tlv)
{
  LDP_TRACE_OUT(handle, "\t Tlv:\n");
  LDP_TRACE_OUT(handle, "\t BaseTlv: uBit = %d\n", tlv->flags.flags.uBit);
  LDP_TRACE_OUT(handle, "\t\t  fBit = %d\n", tlv->flags.flags.fBit);
  LDP_TRACE_OUT(handle, "\t\t  type = %x\n", tlv->flags.flags.tBit);
  LDP_TRACE_OUT(handle, "\t\t  length = %d\n", tlv->length);
}

void printHeader(mpls_instance_handle handle, mplsLdpHeader_t * header)
{
  LDP_TRACE_OUT(handle, "LPD Header : protocolVersion = %d\n",
    header->protocolVersion);
  LDP_TRACE_OUT(handle, "\tpduLength = %d\n", header->pduLength);
  LDP_TRACE_OUT(handle, "\tlsrAddress = %x\n", header->lsrAddress);
  LDP_TRACE_OUT(handle, "\tlabelSpace = %x\n", header->labelSpace);
}

void printCspFlags(mpls_instance_handle handle, mplsLdpCspFlag_t * cspFlags)
{
  LDP_TRACE_OUT(handle, "\tCSP Flags: lad = %d, ld = %d, pvl = %d, res = %d\n",
    cspFlags->lad, cspFlags->ld, cspFlags->pvl, cspFlags->res);
}

void printCspFlagsPerByte(mpls_instance_handle handle, u_short * cspFlags)
{
  u_char *ptr;

  ptr = (u_char *) cspFlags;
  LDP_TRACE_OUT(handle, "\tCSP Flags: (byte 0) %x\n", *ptr++);
  LDP_TRACE_OUT(handle, "\t\t (byte 1) %x\n", *ptr);
}

void printCspTlv(mpls_instance_handle handle, mplsLdpCspTlv_t * csp)
{
  LDP_TRACE_OUT(handle, "\tCSP:\n");
  printTlv(handle, &(csp->baseTlv));
  LDP_TRACE_OUT(handle, "\tcsp        : protocolVersion = %d\n",
    csp->protocolVersion);
  LDP_TRACE_OUT(handle, "\t\tholdTime = %d\n", csp->holdTime);
  LDP_TRACE_OUT(handle, "\t\tmaxPduLen = %d\n", csp->maxPduLen);
  LDP_TRACE_OUT(handle, "\t\trcvLsrAddress = %08x\n", csp->rcvLsrAddress);
  LDP_TRACE_OUT(handle, "\t\trcvLsId = %d\n", csp->rcvLsId);

  printCspFlags(handle, &(csp->flags.flags));
}

void printAspFlags(mpls_instance_handle handle, mplsLdpSPFlag_t * aspFlags)
{
  LDP_TRACE_OUT(handle,
    "\t ASP Flags: mergeType = %d, numLblRng = %d, dir = %d, res = %d\n",
    aspFlags->mergeType, aspFlags->numLblRng, aspFlags->dir, aspFlags->res);
}

void printAspFlagsPerByte(mpls_instance_handle handle, u_int * aspFlags)
{
  u_char *ptr;

  ptr = (u_char *) aspFlags;
  LDP_TRACE_OUT(handle, "\tASP Flags: (byte 0) %x\n", *ptr++);
  LDP_TRACE_OUT(handle, "\t\t (byte 1) %x\n", *ptr++);
  LDP_TRACE_OUT(handle, "\t\t (byte 2) %x\n", *ptr++);
  LDP_TRACE_OUT(handle, "\t\t (byte 3) %x\n", *ptr);
}

void printAtmLabel(mpls_instance_handle handle, mplsLdpAtmLblRng_t * label,
  int i)
{
  LDP_TRACE_OUT(handle,
    "\tATM LABEL (%d) : res1 = %d, minVci = %d, minVpi = %d, res2 = %d, maxVci = %d, maxVpi = %d\n",
    i, label->flags.flags.res1, label->flags.flags.minVci,
    label->flags.flags.minVpi, label->flags.flags.res2,
    label->flags.flags.maxVci, label->flags.flags.maxVpi);
}

void printAspTlv(mpls_instance_handle handle, mplsLdpAspTlv_t * asp)
{
  int i = 0;

  LDP_TRACE_OUT(handle, "\t asp:\n");
  printTlv(handle, &(asp->baseTlv));
  LDP_TRACE_OUT(handle, "\t asp labes (%d)\n",
    (int)(asp->flags.flags.numLblRng));
  for (i = 0; i < (int)(asp->flags.flags.numLblRng); i++) {
    printAtmLabel(handle, &(asp->lblRngList[i]), i);
  }
  printAspFlags(handle, &(asp->flags.flags));
}

void printFspFlags(mpls_instance_handle handle, mplsLdpSPFlag_t * fspFlags)
{
  LDP_TRACE_OUT(handle,
    "\t FSP Flags: mergeType = %d, numLblRng = %d, dir = %d, res = %d\n",
    fspFlags->mergeType, fspFlags->numLblRng, fspFlags->dir, fspFlags->res);
}

void printFspLabel(mpls_instance_handle handle, mplsLdpFrLblRng_t * label, int i)
{
  LDP_TRACE_OUT(handle,
    "\tFR LABEL (%d) : res_max = %d, maxDlci = %d, res_min = %d, len = %d minDlci = %d\n",
    i, label->flags.flags.res_max, label->flags.flags.maxDlci,
    label->flags.flags.res_min, label->flags.flags.len,
    label->flags.flags.minDlci);
}

void printFspTlv(mpls_instance_handle handle, mplsLdpFspTlv_t * fsp)
{
  int i = 0;

  LDP_TRACE_OUT(handle, "\t fsp:\n");
  printTlv(handle, &(fsp->baseTlv));
  LDP_TRACE_OUT(handle, "\t fsp labes (%d)\n",
    (int)(fsp->flags.flags.numLblRng));
  for (i = 0; i < (int)(fsp->flags.flags.numLblRng); i++) {
    printFspLabel(handle, &(fsp->lblRngList[i]), i);
  }
  printFspFlags(handle, &(fsp->flags.flags));
}

void printMsgBase(mpls_instance_handle handle, mplsLdpMsg_t * msg)
{
  LDP_TRACE_OUT(handle, "\tbaseMsg : uBit = %d\n", msg->flags.flags.uBit);
  LDP_TRACE_OUT(handle, "\t\t  msgType = %x\n", msg->flags.flags.msgType);
  LDP_TRACE_OUT(handle, "\t\t  msgLength = %d\n", msg->msgLength);
  LDP_TRACE_OUT(handle, "\t\t  msgId = %d\n", msg->msgId);
}

void printInitMsg(mpls_instance_handle handle, mplsLdpInitMsg_t * initMsg)
{
  LDP_TRACE_OUT(handle, "INIT MSG ***START***:\n");
  printMsgBase(handle, &(initMsg->baseMsg));
  if (initMsg->cspExists) {
    printCspTlv(handle, &(initMsg->csp));
  } else {
    LDP_TRACE_OUT(handle, "\tINIT msg does NOT have CSP\n");
  }
  if (initMsg->aspExists) {
    printAspTlv(handle, &(initMsg->asp));
  } else {
    LDP_TRACE_OUT(handle, "\tINIT msg does NOT have ASP\n");
  }
  if (initMsg->fspExists) {
    printFspTlv(handle, &(initMsg->fsp));
  } else {
    LDP_TRACE_OUT(handle, "\tINIT msg does NOT have FSP\n");
  }
  LDP_TRACE_OUT(handle, "\nINIT MSG ***END***\n");
}

void printRetMsgTlv(mpls_instance_handle handle, mplsLdpRetMsgTlv_t * retMsg)
{
  LDP_TRACE_OUT(handle, "\t retMsgTlv:\n");
  printTlv(handle, &(retMsg->baseTlv));
  LDP_TRACE_OUT(handle, "\t retMsgTlv.data is %s\n", retMsg->data);
}

void printRetPduTlv(mpls_instance_handle handle, mplsLdpRetPduTlv_t * retPdu)
{
  LDP_TRACE_OUT(handle, "\t retPduTlv:\n");
  printTlv(handle, &(retPdu->baseTlv));
  LDP_TRACE_OUT(handle, "\t retPduTlv.data is %s\n", retPdu->data);
}

void printExStatusTlv(mpls_instance_handle handle, mplsLdpExStatusTlv_t * status)
{
  LDP_TRACE_OUT(handle, "\t exStatusTlv:\n");
  printTlv(handle, &(status->baseTlv));
  LDP_TRACE_OUT(handle, "\t exStatus data: value = %d\n", status->value);
}

void printStatusTlv(mpls_instance_handle handle, mplsLdpStatusTlv_t * status)
{
  LDP_TRACE_OUT(handle, "\t statusTlv:\n");
  printTlv(handle, &(status->baseTlv));
  LDP_TRACE_OUT(handle, "\t status data:   msgId = %x\n", status->msgId);
  LDP_TRACE_OUT(handle, "\t\t\tmsgType = %x\n", status->msgType);
  LDP_TRACE_OUT(handle, "\t status Flags:  error = %d\n",
    status->flags.flags.error);
  LDP_TRACE_OUT(handle, "\t\t\tforward = %d\n", status->flags.flags.forward);
  LDP_TRACE_OUT(handle, "\t\t\tstatus = %d\n", status->flags.flags.status);
}

void printNotMsg(mpls_instance_handle handle, mplsLdpNotifMsg_t * notMsg)
{
  LDP_TRACE_OUT(handle, "NOTIF MSG ***START***:\n");
  printMsgBase(handle, &(notMsg->baseMsg));

  if (notMsg->statusTlvExists) {
    printStatusTlv(handle, &(notMsg->status));
  } else {
    LDP_TRACE_OUT(handle, "\tNotif msg does not have Status TLV\n");
  }
  if (notMsg->exStatusTlvExists) {
    printExStatusTlv(handle, &(notMsg->exStatus));
  } else {
    LDP_TRACE_OUT(handle, "\tNotif msg does not have Extended Status TLV\n");
  }
  if (notMsg->retPduTlvExists) {
    printRetPduTlv(handle, &(notMsg->retPdu));
  } else {
    LDP_TRACE_OUT(handle, "\tNotif msg does not have Return PDU\n");
  }
  if (notMsg->retMsgTlvExists) {
    printRetMsgTlv(handle, &(notMsg->retMsg));
  } else {
    LDP_TRACE_OUT(handle, "\tNotif msg does not have Return MSG\n");
  }
  LDP_TRACE_OUT(handle, "NOTIF MSG ***END***:\n");
}

void printCsnTlv(mpls_instance_handle handle, mplsLdpCsnTlv_t * csn)
{
  LDP_TRACE_OUT(handle, "\t csnTlv:\n");
  printTlv(handle, &(csn->baseTlv));
  LDP_TRACE_OUT(handle, "\t csnTlv data: value = %d\n", csn->seqNumber);
}

void printTrAdrTlv(mpls_instance_handle handle, mplsLdpTrAdrTlv_t * trAdr)
{
  LDP_TRACE_OUT(handle, "\t trAdrTlv:\n");
  printTlv(handle, &(trAdr->baseTlv));
  LDP_TRACE_OUT(handle, "\t trAdrTlv data: value = %08x\n", trAdr->address);
}

void printChpTlv(mpls_instance_handle handle, mplsLdpChpTlv_t * chp)
{
  LDP_TRACE_OUT(handle, "\t chpTlv:\n");
  printTlv(handle, &(chp->baseTlv));
  LDP_TRACE_OUT(handle, "\t chpTlv data: holdTime = %d\n", chp->holdTime);
  LDP_TRACE_OUT(handle, "\t chpTlv Flags:  target = %d\n",
    chp->flags.flags.target);
  LDP_TRACE_OUT(handle, "\t\t\trequest = %d\n", chp->flags.flags.request);
  LDP_TRACE_OUT(handle, "\t\t\tres = %d\n", chp->flags.flags.res);
}

void printHelloMsg(mpls_instance_handle handle, mplsLdpHelloMsg_t * helloMsg)
{
  LDP_TRACE_OUT(handle, "HELLO MSG ***START***:\n");
  printMsgBase(handle, &(helloMsg->baseMsg));

  if (helloMsg->chpTlvExists) {
    printChpTlv(handle, &(helloMsg->chp));
  } else {
    LDP_TRACE_OUT(handle, "\tHello msg does not have Chp TLV\n");
  }
  if (helloMsg->trAdrTlvExists) {
    printTrAdrTlv(handle, &(helloMsg->trAdr));
  } else {
    LDP_TRACE_OUT(handle, "\tHello msg does not have TrAdr TLV\n");
  }
  if (helloMsg->csnTlvExists) {
    printCsnTlv(handle, &(helloMsg->csn));
  } else {
    LDP_TRACE_OUT(handle, "\tHello msg does not have Csn TLV\n");
  }
  LDP_TRACE_OUT(handle, "HELLO MSG ***END***:\n");
}

void printKeepAliveMsg(mpls_instance_handle handle,
  mplsLdpKeepAlMsg_t * keepAliveMsg)
{
  LDP_TRACE_OUT(handle, "KEEP ALIVE MSG ***START***:\n");
  printMsgBase(handle, &(keepAliveMsg->baseMsg));
  LDP_TRACE_OUT(handle, "KEEP ALIVE MSG ***END***:\n");
}

void printAdrListTlv(mpls_instance_handle handle, mplsLdpAdrTlv_t * adrList)
{
  u_short i;
  u_short length;

  LDP_TRACE_OUT(handle, "\t adrListTlv:\n");
  printTlv(handle, &(adrList->baseTlv));
  LDP_TRACE_OUT(handle, "\t adrListTlv data: addrFamily = %x\n",
    adrList->addrFamily);

  /* get the current length of the encoding for addresses */

  length = adrList->baseTlv.length - MPLS_ADDFAMFIXLEN;
  LDP_TRACE_OUT(handle, "\t adrListTlv addresses (with %d addresses) :\n",
    length / 4);
  for (i = 0; i < (u_short) (length / 4); i++) {
    if (i % 4 == 0) {
      LDP_TRACE_OUT(handle, "\n\t\t\t");
    }
    LDP_TRACE_OUT(handle, "%02x  ", adrList->address[i]);
  }
  LDP_TRACE_OUT(handle, "\n");
}

void printAddressMsg(mpls_instance_handle handle, mplsLdpAdrMsg_t * adrMsg)
{
  if (adrMsg->baseMsg.flags.flags.msgType == MPLS_ADDR_MSGTYPE) {
    LDP_TRACE_OUT(handle, "ADDRESS MSG ***START***:\n");
  } else if (adrMsg->baseMsg.flags.flags.msgType == MPLS_ADDRWITH_MSGTYPE) {
    LDP_TRACE_OUT(handle, "ADDRESS WITHDRAW MSG ***START***:\n");
  }

  printMsgBase(handle, &(adrMsg->baseMsg));

  if (adrMsg->adrListTlvExists) {
    printAdrListTlv(handle, &(adrMsg->addressList));
  } else {
    LDP_TRACE_OUT(handle, "\tAddress msg does not have addrList Tlv\n");
  }
  if (adrMsg->baseMsg.flags.flags.msgType == MPLS_ADDR_MSGTYPE) {
    LDP_TRACE_OUT(handle, "ADDRESS MSG ***END***:\n");
  } else if (adrMsg->baseMsg.flags.flags.msgType == MPLS_ADDRWITH_MSGTYPE) {
    LDP_TRACE_OUT(handle, "ADDRESS WITHDRAW MSG ***END***:\n");
  }
}

void printFecListTlv(mpls_instance_handle handle, mplsLdpFecTlv_t * fecTlv)
{
  u_short i;

  LDP_TRACE_OUT(handle, "\t fecTlv:\n");
  printTlv(handle, &(fecTlv->baseTlv));
  LDP_TRACE_OUT(handle, "\t\tfecTlv->numberFecElements = %d\n",
    fecTlv->numberFecElements);
  for (i = 0; i < fecTlv->numberFecElements; i++) {
    LDP_TRACE_OUT(handle, "\t\telem %d type is %d\n", i,
      fecTlv->fecElemTypes[i]);
    if ((fecTlv->fecElemTypes[i] == 2) || (fecTlv->fecElemTypes[i] == 3)) {
      LDP_TRACE_OUT(handle,
        "\t\tFec Element : type = %d, addFam = %x, preLen = %d, address = %x\n",
        fecTlv->fecElArray[i].addressEl.type,
        fecTlv->fecElArray[i].addressEl.addressFam,
        fecTlv->fecElArray[i].addressEl.preLen,
        fecTlv->fecElArray[i].addressEl.address);
    }
  }
  LDP_TRACE_OUT(handle, "\n");
  LDP_TRACE_OUT(handle, "\tfecTlv.wcElemExists = %d\n", fecTlv->wcElemExists);

}

void printLblMsgIdTlv(mpls_instance_handle handle,
  mplsLdpLblMsgIdTlv_t * lblMsgId)
{
  LDP_TRACE_OUT(handle, "\t lblMsgIdTlv:\n");
  printTlv(handle, &(lblMsgId->baseTlv));
  LDP_TRACE_OUT(handle, "\t LblMsgId data:  msgId = %d\n", lblMsgId->msgId);
}

void printPathVecTlv(mpls_instance_handle handle, mplsLdpPathTlv_t * pathVec)
{
  u_int i, numlsrId;

  LDP_TRACE_OUT(handle, "\t pathVecTlv:\n");
  printTlv(handle, &(pathVec->baseTlv));
  LDP_TRACE_OUT(handle, "\t PathVec data: ");

  numlsrId = pathVec->baseTlv.length / 4;

  for (i = 0; i < numlsrId; i++) {
    if (i == 0) {
      LDP_TRACE_OUT(handle, "lsrId[%d] = %x\n", i, pathVec->lsrId[i]);
    } else {
      LDP_TRACE_OUT(handle, "\t\t\tlsrId[%d] = %x\n", i, pathVec->lsrId[i]);
    }
  }
  LDP_TRACE_OUT(handle, "\n");
}

void printHopTlv(mpls_instance_handle handle, mplsLdpHopTlv_t * hopCount)
{
  LDP_TRACE_OUT(handle, "\t hopCountTlv:\n");
  printTlv(handle, &(hopCount->baseTlv));
  LDP_TRACE_OUT(handle, "\t hopCount data:  hcValue = %d\n", hopCount->hcValue);
}

void printFrLblTlv(mpls_instance_handle handle, mplsLdpFrLblTlv_t * fr)
{
  LDP_TRACE_OUT(handle, "\t frTlv :\n");
  printTlv(handle, &(fr->baseTlv));
  LDP_TRACE_OUT(handle, "\t Fr flags: res = %d\n", fr->flags.flags.res);
  LDP_TRACE_OUT(handle, "\t\t len = %d\n", fr->flags.flags.len);
  LDP_TRACE_OUT(handle, "\t\tdlci = %d\n", fr->flags.flags.dlci);
}

void printAtmLblTlv(mpls_instance_handle handle, mplsLdpAtmLblTlv_t * atm)
{
  LDP_TRACE_OUT(handle, "\t atmTlv :\n");
  printTlv(handle, &(atm->baseTlv));
  LDP_TRACE_OUT(handle, "\t Atm flags: res = %d\n", atm->flags.flags.res);
  LDP_TRACE_OUT(handle, "\t\t v = %d\n", atm->flags.flags.v);
  LDP_TRACE_OUT(handle, "\t\tvpi = %d\n", atm->flags.flags.vpi);
  LDP_TRACE_OUT(handle, "\t Atm data : vci = %d\n", atm->vci);
}

void printGenLblTlv(mpls_instance_handle handle, mplsLdpGenLblTlv_t * genLbl)
{
  LDP_TRACE_OUT(handle, "\t genLblTlv:\n");
  printTlv(handle, &(genLbl->baseTlv));
  LDP_TRACE_OUT(handle, "\t genLbl data: label = %d\n", genLbl->label);
}

void printLlbMapMsg(mpls_instance_handle handle, mplsLdpLblMapMsg_t * lblMapMsg)
{
  LDP_TRACE_OUT(handle, "LABEL MAPPING MSG ***START***:\n");
  printMsgBase(handle, &(lblMapMsg->baseMsg));

  if (lblMapMsg->fecTlvExists) {
    printFecListTlv(handle, &(lblMapMsg->fecTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel mapping msg does not have fec Tlv\n");
  }
  if (lblMapMsg->genLblTlvExists) {
    printGenLblTlv(handle, &(lblMapMsg->genLblTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel mapping msg does not have gen label Tlv\n");
  }
  if (lblMapMsg->atmLblTlvExists) {
    printAtmLblTlv(handle, &(lblMapMsg->atmLblTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel mapping msg does not have atm label Tlv\n");
  }
  if (lblMapMsg->frLblTlvExists) {
    printFrLblTlv(handle, &(lblMapMsg->frLblTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel mapping msg does not have fr label Tlv\n");
  }
  if (lblMapMsg->hopCountTlvExists) {
    printHopTlv(handle, &(lblMapMsg->hopCountTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel mapping msg does not have hop count Tlv\n");
  }
  if (lblMapMsg->pathVecTlvExists) {
    printPathVecTlv(handle, &(lblMapMsg->pathVecTlv));
  } else {
    LDP_TRACE_OUT(handle,
      "\tLabel mapping msg does not have path vector Tlv\n");
  }
  if (lblMapMsg->lblMsgIdTlvExists) {
    printLblMsgIdTlv(handle, &(lblMapMsg->lblMsgIdTlv));
  } else {
    LDP_TRACE_OUT(handle,
      "\tLabel mapping msg does not have label messageId Tlv\n");
  }
  if (lblMapMsg->lspidTlvExists) {
    printLspIdTlv(handle, &(lblMapMsg->lspidTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel mapping msg does not have LSPID Tlv\n");
  }
  if (lblMapMsg->trafficTlvExists) {
    printTrafficTlv(handle, &(lblMapMsg->trafficTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel mapping msg does not have traffic Tlv\n");
  }
  LDP_TRACE_OUT(handle, "LABEL MAPPING MSG ***END***:\n");
}

void printErFlags(mpls_instance_handle handle, mplsLdpErFlag_t * flags)
{
  LDP_TRACE_OUT(handle, "\t\tER FLAGS: l = %d, res = %d\n",
    flags->l, flags->res);
}

void printErIPFlags(mpls_instance_handle handle, mplsLdpErIPFlag_t * flags)
{
  LDP_TRACE_OUT(handle, "\t\tER IP FLAGS: l = %d, res = %d, preLen = %d\n",
    flags->l, flags->res, flags->preLen);
}

void printErHop(mpls_instance_handle handle, mplsLdpErHop_t * erHop,
  u_short type)
{
  int i;

  switch (type) {
    case MPLS_ERHOP_IPV4_TLVTYPE:
      {
        printErIPFlags(handle, &(erHop->erIpv4.flags.flags));
        LDP_TRACE_OUT(handle, "\t\t IPv4: address = %x\n",
          erHop->erIpv4.address);
        break;
      }
    case MPLS_ERHOP_IPV6_TLVTYPE:
      {
        printErIPFlags(handle, &(erHop->erIpv6.flags.flags));
        LDP_TRACE_OUT(handle, "\t\t IPv6: address ");
        for (i = 0; i < MPLS_IPV6ADRLENGTH; i++) {
          LDP_TRACE_OUT(handle, "\t\t a[%d] = %x\n", i,
            erHop->erIpv6.address[i]);
        }
        break;
      }
    case MPLS_ERHOP_AS_TLVTYPE:
      {
        printErFlags(handle, &(erHop->erAs.flags.flags));
        LDP_TRACE_OUT(handle, "\t\t ASnumber: asNumber = %d\n",
          erHop->erAs.asNumber);
        break;
      }
    case MPLS_ERHOP_LSPID_TLVTYPE:
      {
        printErFlags(handle, &(erHop->erLspId.flags.flags));
        LDP_TRACE_OUT(handle, "\t\t LSPID: lspid = %d, routerId = %d\n",
          erHop->erLspId.lspid, erHop->erLspId.routerId);
        break;
      }
    default:
      {
        LDP_TRACE_OUT(handle, "UNKNWON ER HOP type = %d\n", type);
      }
  }
}

void printErTlv(mpls_instance_handle handle, mplsLdpErTlv_t * erTlv)
{
  u_short i;

  LDP_TRACE_OUT(handle, "\t erTlv:\n");
  printTlv(handle, &(erTlv->baseTlv));
  LDP_TRACE_OUT(handle, "\t erTlv has %d ErHops\n", erTlv->numberErHops);
  for (i = 0; i < erTlv->numberErHops; i++) {
    LDP_TRACE_OUT(handle, "\tTYPE[%i] = %x\n", i, erTlv->erHopTypes[i]);
    printErHop(handle, &(erTlv->erHopArray[i]), erTlv->erHopTypes[i]);
  }
}

void printTrafficFlags(mpls_instance_handle handle,
  mplsLdpTrafficFlag_t * traflag)
{
  LDP_TRACE_OUT(handle,
    "\t\tTraffic flags: res = %d, F6 = %d, F5 = %d, F4 = %d, F3 = %d, F2 = %d, F1 = %d\n",
    traflag->res, traflag->f6Bit, traflag->f5Bit, traflag->f4Bit,
    traflag->f3Bit, traflag->f2Bit, traflag->f1Bit);
}

void printTrafficTlv(mpls_instance_handle handle,
  mplsLdpTrafficTlv_t * trafficTlv)
{
  LDP_TRACE_OUT(handle, "\t trafficTlv:\n");
  printTlv(handle, &(trafficTlv->baseTlv));
  printTrafficFlags(handle, &(trafficTlv->flags.flags));
  LDP_TRACE_OUT(handle,
    "\t trafficTlv data: freq = %d, res = %d, weight = %d\n", trafficTlv->freq,
    trafficTlv->res, trafficTlv->weight);
  LDP_TRACE_OUT(handle, "\t trafficTlv param: \n");
  LDP_TRACE_OUT(handle, "\t\t PDR = %f (%x)\n", trafficTlv->pdr.pdr,
    *(u_int *) & (trafficTlv->pdr.pdr));
  LDP_TRACE_OUT(handle, "\t\t PBS = %f (%x)\n", trafficTlv->pbs.pbs,
    *(u_int *) & (trafficTlv->pbs.pbs));
  LDP_TRACE_OUT(handle, "\t\t CDR = %f (%x)\n", trafficTlv->cdr.cdr,
    *(u_int *) & (trafficTlv->cdr.cdr));
  LDP_TRACE_OUT(handle, "\t\t CBS = %f (%x)\n", trafficTlv->cbs.cbs,
    *(u_int *) & (trafficTlv->cbs.cbs));
  LDP_TRACE_OUT(handle, "\t\t EBS = %f (%x)\n", trafficTlv->ebs.ebs,
    *(u_int *) & (trafficTlv->ebs.ebs));
}

void printLlbReqMsg(mpls_instance_handle handle, mplsLdpLblReqMsg_t * lblReqMsg)
{
  LDP_TRACE_OUT(handle, "LABEL REQUEST MSG ***START***:\n");
  printMsgBase(handle, &(lblReqMsg->baseMsg));

  if (lblReqMsg->fecTlvExists) {
    printFecListTlv(handle, &(lblReqMsg->fecTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel request msg does not have fec Tlv\n");
  }
  if (lblReqMsg->hopCountTlvExists) {
    printHopTlv(handle, &(lblReqMsg->hopCountTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel request msg does not have hop count Tlv\n");
  }
  if (lblReqMsg->pathVecTlvExists) {
    printPathVecTlv(handle, &(lblReqMsg->pathVecTlv));
  } else {
    LDP_TRACE_OUT(handle,
      "\tLabel request msg does not have path vector Tlv\n");
  }
  if (lblReqMsg->lblMsgIdTlvExists) {
    printTlv(handle, &(lblReqMsg->lblMsgIdTlv.baseTlv));
  } else {
    LDP_TRACE_OUT(handle,
      "\tLabel request msg does not have return msgId Tlv\n");
  }
  if (lblReqMsg->erTlvExists) {
    printErTlv(handle, &(lblReqMsg->erTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel request msg does not have cr Tlv\n");
  }
  if (lblReqMsg->trafficTlvExists) {
    printTrafficTlv(handle, &(lblReqMsg->trafficTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel request msg does not have traffic Tlv\n");
  }
  if (lblReqMsg->lspidTlvExists) {
    printLspIdTlv(handle, &(lblReqMsg->lspidTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel request msg does not have LSPID Tlv\n");
  }
  if (lblReqMsg->pinningTlvExists) {
    printPinningTlv(handle, &(lblReqMsg->pinningTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel request msg does not have Pinning Tlv\n");
  }
  if (lblReqMsg->recClassTlvExists) {
    printResClsTlv(handle, &(lblReqMsg->resClassTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel request msg does not have ResClass Tlv\n");
  }
  if (lblReqMsg->preemptTlvExists) {
    printPreemptTlv(handle, &(lblReqMsg->preemptTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel request msg does not have Preempt Tlv\n");
  }
  LDP_TRACE_OUT(handle, "LABEL REQUEST MSG ***END***:\n");
}

void printLbl_W_R_Msg(mpls_instance_handle handle, mplsLdpLbl_W_R_Msg_t * msg)
{
  if (msg->baseMsg.flags.flags.msgType == MPLS_LBLWITH_MSGTYPE) {
    LDP_TRACE_OUT(handle, "LABEL WITHDRAW MSG ***START***:\n");
  } else if (msg->baseMsg.flags.flags.msgType == MPLS_LBLREL_MSGTYPE) {
    LDP_TRACE_OUT(handle, "LABEL RELEASE MSG ***START***:\n");
  }
  printMsgBase(handle, &(msg->baseMsg));

  if (msg->fecTlvExists) {
    printFecListTlv(handle, &(msg->fecTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel msg does not have fec Tlv\n");
  }
  if (msg->genLblTlvExists) {
    printGenLblTlv(handle, &(msg->genLblTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel msg does not have gen Tlv\n");
  }
  if (msg->atmLblTlvExists) {
    printAtmLblTlv(handle, &(msg->atmLblTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel msg does not have atm Tlv\n");
  }
  if (msg->frLblTlvExists) {
    printFrLblTlv(handle, &(msg->frLblTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel msg does not have fr Tlv\n");
  }
  if (msg->lspidTlvExists) {
    printLspIdTlv(handle, &(msg->lspidTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel msg does not have LSPID Tlv\n");
  }
  if (msg->baseMsg.flags.flags.msgType == MPLS_LBLWITH_MSGTYPE) {
    LDP_TRACE_OUT(handle, "LABEL WITHDRAW MSG *** END ***:\n");
  } else if (msg->baseMsg.flags.flags.msgType == MPLS_LBLREL_MSGTYPE) {
    LDP_TRACE_OUT(handle, "LABEL RELEASE MSG *** END ***:\n");
  }
}

void printPreemptTlv(mpls_instance_handle handle,
  mplsLdpPreemptTlv_t * preemptTlv)
{
  LDP_TRACE_OUT(handle, "\t preemptTlv:\n");
  printTlv(handle, &(preemptTlv->baseTlv));
  LDP_TRACE_OUT(handle,
    "\t preemptTlv data: setPrio = %d, holdPrio = %d, res = %d\n",
    preemptTlv->setPrio, preemptTlv->holdPrio, preemptTlv->res);
}

void printResClsTlv(mpls_instance_handle handle, mplsLdpResClsTlv_t * tlv)
{
  LDP_TRACE_OUT(handle, "\t resClsTlv:\n");
  printTlv(handle, &(tlv->baseTlv));
  LDP_TRACE_OUT(handle, "\t resClsTlv data: rsCls = %x\n", tlv->rsCls);
}

void printLspIdTlv(mpls_instance_handle handle, mplsLdpLspIdTlv_t * tlv)
{
  LDP_TRACE_OUT(handle, "\t lspIdTlv:\n");
  printTlv(handle, &(tlv->baseTlv));
  LDP_TRACE_OUT(handle,
    "\t lspIdTlv data: res = %d, localCrlspId = %d, routerId = %x\n", tlv->res,
    tlv->localCrlspId, tlv->routerId);
}

void printPinningTlv(mpls_instance_handle handle, mplsLdpPinningTlv_t * tlv)
{
  LDP_TRACE_OUT(handle, "\t pinningTlv:\n");
  printTlv(handle, &(tlv->baseTlv));
  LDP_TRACE_OUT(handle, "\t pinningTlv data: pBit = %d, res = %d\n",
    tlv->flags.flags.pBit, tlv->flags.flags.res);
}

void printLlbAbortMsg(mpls_instance_handle handle, mplsLdpLblAbortMsg_t * lblMsg)
{
  LDP_TRACE_OUT(handle, "LABEL ABORT MSG ***START***:\n");
  printMsgBase(handle, &(lblMsg->baseMsg));

  if (lblMsg->fecTlvExists) {
    printFecListTlv(handle, &(lblMsg->fecTlv));
  } else {
    LDP_TRACE_OUT(handle, "\tLabel abort msg does not have fec Tlv\n");
  }
  if (lblMsg->lblMsgIdTlvExists) {
    printLblMsgIdTlv(handle, &(lblMsg->lblMsgIdTlv));
  } else {
    LDP_TRACE_OUT(handle,
      "\tLabel abort msg does not have label messageId Tlv\n");
  }
  LDP_TRACE_OUT(handle, "LABEL ABORT MSG ***END***:\n");
}

/* 
 *   Routine to convert hex string to ascii string
 */

int converHexToAscii(u_char * buffHex, int buffHexLen, u_char * buffAscii)
{
  /* convert the hexEncrypP hex string to a char sting */
  int i = 0;
  int j = 0;
  char c, c1;
  u_char *p = buffHex;
  u_char *q = buffAscii;

  for (i = 0; i < buffHexLen; i += 2, j++) {
    c = *p;
    p++;
    c1 = *p;
    p++;
    if (c >= '0' && c <= '9')
      c -= '0';
    else if (c >= 'A' && c <= 'F')
      c -= 'A' - 0xa;
    else if (c >= 'a' && c <= 'f')
      c -= 'a' - 0xa;
    else
      return 0;
    if (c1 >= '0' && c1 <= '9')
      c1 -= '0';
    else if (c1 >= 'A' && c1 <= 'F')
      c1 -= 'A' - 0xa;
    else if (c1 >= 'a' && c1 <= 'f')
      c1 -= 'a' - 0xa;
    else
      return 0;

    *q++ = (c << 4) + (c1 & 0x0f);
  }
  return j;

}                               /* End : converHexToAscii */

/* 
 *   Routine to convert ascii string to hex string
 */
int converAsciiToHex(u_char * buffHex, int buffAsciiLen, u_char * buffAscii)
{
  int i;
  u_char *p2 = buffHex;
  u_char *p1 = buffAscii;
  u_char buf[3];

  for (i = 0; i < buffAsciiLen; i++) {
    memset(buf, 0, 3);
    sprintf((char *)buf, "%02x", *p1++);
    memcpy(p2, buf, 2);
    p2 += strlen((char *)buf);
  }
  *p2 = '\0';

  p2 = buffHex;
  for (i = 0; i < 2 * buffAsciiLen; i++) {
    PRINT_OUT("%c", *p2++);
  }
  PRINT_OUT("\n");
  return i;

}                               /* End : converAsciiToHex */

/*****************************************************************************
* This section includes one example  of hex buffers which contains encoding  *
* for a pdu header and a request message.                                    *
*                                                                            *
* the hex buffer for the request message contains (where q represents the end*
* of the buffer):                                                            *
*                                                                            *
* 0001009AC00003050002040100900000000806010000010000100200011B00194059030001 *
* 042F7D308308210008000000013A1D65030800003008040008000000193A1D651708040008 * 
* 800000053A1D6503080400088000000F3A1D650D08040008000000233A1D65210810001824 * 
* 01000040e3333342c8000040e00000447a0000412000000823000480000000082200040ABC * 
* DEFF0820000407070000q                                                      *
*                                                                            *
* Make sure that when copy and paste the buffer, there are no new line chars *
* or blanks.                                                                 *
* When decoding the above buffer, the following debug output should show if  *
* the debug flag is defined and set:                                         *
*                                                                            *
*LPD Header : protocolVersion = 1                                            *
*        pduLength = 154                                                     *
*        lsrAddress = c0000305                                               *
*        labelSpace = 2                                                      *
*                                                                            *
*LABEL REQUEST MSG ***START***:                                              *
*        baseMsg : msgType = 401                                             *
*                msgLength = 144                                             *
*                msgId = 8                                                   *
*         fecTlv:                                                            *
*         Tlv:                                                               *
*         BaseTlv: type = 100                                                *
*                  length = 16                                               *
*                  uBit = 0                                                  *
*                  fBit = 0                                                  *
*                fecTlv->numberFecElements = 2                               *
*                elem 0 type is 2                                            *
*                Fec Element : type = 2, addFam = 1, preLen = 27,            *
*                              address = 194059                              *
*                elem 1 type is 3                                            *
*                Fec Element : type = 3, addFam = 1, preLen = 4,             *
*                              address = 2f7d3083                            *
*                                                                            * 
*        fecTlv.wcElemExists = 0                                             *
*        Label request msg does not have cos label Tlv                       *
*        Label request msg does not have hop count Tlv                       *
*        Label request msg does not have path vector Tlv                     *
*         Tlv:                                                               *
*         BaseTlv: type = 601                                                *
*                  length = 0                                                *
*                  uBit = 0                                                  *
*                  fBit = 0                                                  *
*         erTlv:                                                             *
*         Tlv:                                                               *
*         BaseTlv: type = 800                                                *
*                  length = 48                                               *
*                  uBit = 0                                                  *
*                  fBit = 0                                                  *
*         erTlv has 4 ErHops                                                 *
*        TYPE[0] = 804                                                       *
*                ER FLAGS: l = 0, res = 0                                    *
*                 LSPID: lspid = 25, routerId = 975004951                    *
*        TYPE[1] = 804                                                       *
*                ER FLAGS: l = 1, res = 0                                    *
*                 LSPID: lspid = 5, routerId = 975004931                     *
*        TYPE[2] = 804                                                       *
*                ER FLAGS: l = 1, res = 0                                    *
*                 LSPID: lspid = 15, routerId = 975004941                    *
*        TYPE[3] = 804                                                       *
*                ER FLAGS: l = 0, res = 0                                    *
*                 LSPID: lspid = 35, routerId = 975004961                    *
*         trafficTlv:                                                        *
*         Tlv:                                                               *
*         BaseTlv: type = 810                                                *
*                  length = 24                                               *
*                  uBit = 0                                                  *
*                  fBit = 0                                                  *
*                Traffic flags: res = 0, F6 = 1, F5 = 0, F4 = 0, F3 = 1,     * 
*                                        F2 = 0, F1 = 0                      *
*         trafficTlv data: freq = 1, res = 0, weight = 0                     *
*         trafficTlv param:                                                  *
*                 PDR = 7.1(40e33333)                                        *
*                 PBS = 100.0(42c80000)                                      *
*                 CDR = 7.0(40e00000)                                        *
*                 CBS = 1000.0(447a0000)                                     *
*                 EBS = 10.0(41200000)                                       *
*         lspIdTlv:                                                          *
*         Tlv:                                                               *
*         BaseTlv: type = 821                                                *
*                  length = 8                                                *
*                  uBit = 0                                                  *
*                  fBit = 0                                                  *
*         lspIdTlv data: res = 0, localCrlspId = 1, routerId = 3a1d6503      *
*         pinningTlv:                                                        *
*         Tlv:                                                               *
*         BaseTlv: type = 823                                                *
*                  length = 4                                                *
*                  uBit = 0                                                  *
*                  fBit = 0                                                  *
*         pinningTlv data: pBit = 1, res = 0                                 *
*         resClsTlv:                                                         *
*         Tlv:                                                               *
*         BaseTlv: type = 822                                                *
*                  length = 4                                                *
*                  uBit = 0                                                  *
*                  fBit = 0                                                  *
*         resClsTlv data: rsCls = abcdeff                                    *
*         preemptTlv:                                                        *
*         Tlv:                                                               *
*         BaseTlv: type = 820                                                *
*                  length = 4                                                *
*                  uBit = 0                                                  *
*                  fBit = 0                                                  *
*         preemptTlv data: setPrio = 7, holdPrio = 7, res = 0                *
*LABEL REQUEST MSG ***END***:                                                *
*****************************************************************************/
