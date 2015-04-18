#ifndef _LDP_MPLS_H_
#define _LDP_MPLS_H_

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
 *           bzero(buffer, 500);                                  	      *
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

#include "ldp_struct.h"
#include "mpls_bitfield.h"
#include <sys/types.h>
#include <string.h>

#define MEM_COPY(X, Y, Z) memcpy(X, Y, Z)

/* macros used to decode the entire LDP; they declare local var for
   different type of messages */

/* debug macros */
#define PRINT_OUT(args...)
#define PRINT_ERR(args...)

/*
 *    MESSAGE TYPE CONSTANS & TLV CONSTANTS
 */

#define MPLS_LDP_HDRSIZE         10 /* the size for mpls ldp hdr  */
#define MPLS_TLVFIXLEN           4 /* type + len                 */
#define MPLS_MSGIDFIXLEN         4 /* type + len                 */
#define MPLS_LDPIDLEN            6
#define MPLS_PDUMAXLEN           4096 /* octets                    */
#define MPLS_VERSION             0x0001
#define MPLS_IPV4ADDRFAMILYN     0x0100 /* rfc 1700 (network order)  */
#define MPLS_INIFINITE_TIMEVAL   0xfffff

/* for initialize message */
#define MPLS_INIT_MSGTYPE        0x0200 /* initialization msg          */
#define MPLS_CSP_TLVTYPE         0x0500 /* common params for init msg  */
#define MPLS_ASP_TLVTYPE         0x0501 /* atm session params          */
#define MPLS_FSP_TLVTYPE         0x0502 /* frame relay session params  */
#define MPLS_ASPFIXLEN           4 /* M + N + D + res             */
#define MPLS_FSPFIXLEN           4 /* M + N + res                 */
#define MPLS_CSPFIXLEN           14 /* protocolV + ... + ldp ids   */
#define MPLS_ATMLBLMAXLEN        10
#define MPLS_ATMLRGFIXLEN        8
#define MPLS_FRLRGFIXLEN         8
#define MPLS_ASP_NOMERGE         0
#define MPLS_ASP_VPMERGE         1
#define MPLS_ASP_VCMERGE         2
#define MPLS_ASP_VPVCMERGE       3
#define MPLS_FRLBLMAXLEN         10
#define MPLS_FRDLCI10BITS        0
#define MPLS_FRDLCI17BITS        1
#define MPLS_FRDLCI23BITS        2

/* for notification message */
#define MPLS_NOT_MSGTYPE         0x0001 /* notification msg            */
#define MPLS_NOT_ST_TLVTYPE      0x0300 /* status tlv for not msg      */
#define MPLS_NOT_ES_TLVTYPE      0x0301 /* extended status for not msg */
#define MPLS_NOT_RP_TLVTYPE      0x0302 /* returned PDU for not msg    */
#define MPLS_NOT_RM_TLVTYPE      0x0303 /* returned msg for not msg    */
#define MPLS_STATUSFIXLEN        10 /* status code + id + type     */
#define MPLS_EXSTATUSLEN         4
#define MPLS_NOT_MAXSIZE         MPLS_PDUMAXLEN - MPLS_TLVFIXLEN - \
				 MPLS_MSGIDFIXLEN

/* for hello message */
#define MPLS_HELLO_MSGTYPE       0x0100 /* hello msg                   */
#define MPLS_CHP_TLVTYPE         0x0400 /* Common Hello Param Tlv      */
#define MPLS_TRADR_TLVTYPE       0x0401 /* Transport Address Param Tlv */
#define MPLS_CSN_TLVTYPE         0x0402 /* Conf Seq Number Param Tlv   */
#define MPLS_CHPFIXLEN           4
#define MPLS_CSNFIXLEN           4
#define MPLS_TRADRFIXLEN         4

/* for keep alive message */
#define MPLS_KEEPAL_MSGTYPE      0x0201 /* keep alive msg              */

/* for address messages */
#define MPLS_ADDR_MSGTYPE        0x0300 /* address msg                 */
#define MPLS_ADDRWITH_MSGTYPE    0x0301 /* address withdraw msg        */
#define MPLS_ADDRLIST_TLVTYPE    0x0101 /* addrss list tlv type        */
#define MPLS_IPv4LEN             4
#define MPLS_ADDFAMFIXLEN        2
#define MPLS_ADDLISTMAXLEN       (MPLS_PDUMAXLEN - (2*MPLS_TLVFIXLEN) - \
			         MPLS_MSGIDFIXLEN - MPLS_ADDFAMFIXLEN)
#define MPLS_MAXNUMBERADR        MPLS_ADDLISTMAXLEN / 4

/* for label mapping message */
#define MPLS_LBLMAP_MSGTYPE      0x0400 /* label mapping msg           */
#define MPLS_FEC_TLVTYPE         0x0100 /* label mapping msg           */
#define MPLS_GENLBL_TLVTYPE      0x0200 /* generic label tlv           */
#define MPLS_ATMLBL_TLVTYPE      0x0201 /* atm label tlv               */
#define MPLS_FRLBL_TLVTYPE       0x0202 /* frame relay label tlv       */
#define MPLS_HOPCOUNT_TLVTYPE    0x0103 /* ho count tlv                */
#define MPLS_PATH_TLVTYPE        0x0104 /* path vector tlv             */
#define MPLS_REQMSGID_TLVTYPE    0x0600 /* lbl request msg id tlv      */
#define MPLS_WC_FEC              0x01 /* wildcard fec element        */
#define MPLS_PREFIX_FEC          0x02 /* prefix fec element          */
#define MPLS_HOSTADR_FEC         0x03 /* host addr fec element       */
#define MPLS_CRLSP_FEC           0x04 /* crlsp fec element           */
#define MPLS_PW_ID_FEC           0x80 /*pseudowire id fec element
					(0x80=128) add by timothy*/
#define MPLS_FECMAXLEN           (MPLS_PDUMAXLEN - (2*MPLS_TLVFIXLEN) - \
			         MPLS_MSGIDFIXLEN)
#define MPLS_LBLFIXLEN           4 /* v + vpi + vci + res         */
#define MPLS_HOPCOUNTFIXLEN      1 /* v + vpi + vci + res         */
#define MPLS_FEC_ELEMTYPELEN     1
#define MPLS_FEC_PRELENLEN       1
#define MPLS_FEC_ADRFAMLEN       2
#define MPLS_FEC_CRLSPLEN        4 /* length of cr lsp fec        */
#define MPLS_FEC_PWIDTYPELEN     2 /*length of PW type field of PWid FEC*/ //add by timothy
#define MPLS_FEC_PWIDGROUPIDLEN  4 /*length of PW Group ID field of PWid FEC*/ //add by timothy
#define MPLS_FEC_PWIDPWIDLEN     4 /*length of PW ID field of PWid FEC*/ //add by timothy
#define MPLS_MAXHOPSNUMBER       20 /* max # hops in path vector   */
#define MPLS_MAXNUMFECELEMENT    10 /* max # of fec elements       */

/* for label request message */
#define MPLS_LBLREQ_MSGTYPE      0x0401 /* label request msg           */
#define MPLS_LBLMSGID_TLVTYPE    0x0601 /* lbl return msg id tlv       */
#define MPLS_ADR_FEC_FIXLEN	 (MPLS_FEC_ELEMTYPELEN + MPLS_FEC_PRELENLEN + MPLS_FEC_ADRFAMLEN)

/* for label withdraw and release messages */
#define MPLS_LBLWITH_MSGTYPE     0x0402 /* label withdraw msg          */
#define MPLS_LBLREL_MSGTYPE      0x0403 /* label release msg           */

/* for ER tlvs */
#define MPLS_ER_TLVTYPE          0x0800 /* constraint routing tlv      */
#define MPLS_TRAFFIC_TLVTYPE     0x0810 /* traffic parameters tlv      */
#define MPLS_PDR_TLVTYPE         0x0811 /* traffic peak data rate tlv  */
#define MPLS_CDR_TLVTYPE         0x0812 /* committed data rate tlv     */
#define MPLS_CBT_TLVTYPE         0x0813 /* committed burst tolerance   */
#define MPLS_PREEMPT_TLVTYPE     0x0820 /* preemption tlv              */
#define MPLS_LSPID_TLVTYPE       0x0821 /* lspid tlv                   */
#define MPLS_RESCLASS_TLVTYPE    0x0822 /* resource class tlv          */
#define MPLS_PINNING_TLVTYPE     0x0823 /* route pinning tlv           */
#define MPLS_ERHOP_IPV4_TLVTYPE  0x801 /* explicit routing ipv4 tlv   */
#define MPLS_ERHOP_IPV6_TLVTYPE  0x802 /* explicit routing ipv6 tlv   */
#define MPLS_ERHOP_AS_TLVTYPE    0x803 /* explicit routing autonomous
                                          system number tlv           */
#define MPLS_ERHOP_LSPID_TLVTYPE 0x804 /* explicit routing lspid tlv  */
#define MPLS_ERHOP_IPV4_FIXLEN   8 /* fix length in bytes         */
#define MPLS_ERHOP_IPV6_FIXLEN   20 /* fix length in bytes         */
#define MPLS_ERHOP_AS_FIXLEN     4 /* fix length in bytes         */
#define MPLS_ERHOP_LSPID_FIXLEN  8 /* fix length in bytes         */
#define MPLS_IPV6ADRLENGTH       16
#define MPLS_MAX_ER_HOPS         20 /* decent number of hops; 
                                       change if required          */
#define MPLS_PREEMPTTLV_FIXLEN   4 /* setPrio + holdPrio + res    */
#define MPLS_LSPIDTLV_FIXLEN     8 /* res + crlspId + routerId    */
#define MPLS_TRAFFICPARAMLENGTH  4 /* traffic parameters length   */

/* for label abort request message */
#define MPLS_LBLABORT_MSGTYPE 0x0404 /* label abort request msg     */

/*
 * Error codes
 */

#define MPLS_ENC_BUFFTOOSMALL    -1
#define MPLS_DEC_BUFFTOOSMALL    -2
#define MPLS_ENC_TLVERROR        -3
#define MPLS_DEC_TLVERROR        -4
#define MPLS_ENC_ATMLBLERROR     -5
#define MPLS_DEC_ATMLBLERROR     -6
#define MPLS_ENC_BASEMSGERROR    -7
#define MPLS_DEC_BASEMSGERROR    -8
#define MPLS_ENC_CSPERROR        -9
#define MPLS_DEC_CSPERROR        -10
#define MPLS_ENC_ASPERROR        -11
#define MPLS_DEC_ASPERROR        -12
#define MPLS_ENC_FSPERROR        -13
#define MPLS_DEC_FSPERROR        -14
#define MPLS_ENC_STATUSERROR     -16
#define MPLS_DEC_STATUSERROR     -17
#define MPLS_ENC_EXSTATERROR     -18
#define MPLS_DEC_EXSTATERROR     -19
#define MPLS_ENC_RETPDUERROR     -20
#define MPLS_DEC_RETPDUERROR     -21
#define MPLS_ENC_RETMSGERROR     -22
#define MPLS_DEC_RETMSGERROR     -23
#define MPLS_PDU_LENGTH_ERROR    -24
#define MPLS_ENC_CHPERROR        -25
#define MPLS_DEC_CHPERROR        -26
#define MPLS_ENC_CSNERROR        -27
#define MPLS_DEC_CSNERROR        -28
#define MPLS_ENC_TRADRERROR      -29
#define MPLS_DEC_TRADRERROR      -30
#define MPLS_ENC_ADRLISTERROR    -31
#define MPLS_DEC_ADRLISTERROR    -32
#define MPLS_WC_FECERROR         -33
#define MPLS_PATHVECTORERROR     -34
#define MPLS_ENC_FECERROR        -35
#define MPLS_DEC_FECERROR        -36
#define MPLS_ENC_GENLBLERROR     -37
#define MPLS_DEC_GENLBLERROR     -38
#define MPLS_ENC_MAPATMERROR     -39
#define MPLS_DEC_MAPATMERROR     -40
#define MPLS_ENC_FRLBLERROR      -41
#define MPLS_DEC_FRLBLERROR      -42
#define MPLS_ENC_COSERROR        -43
#define MPLS_DEC_COSERROR        -44
#define MPLS_ENC_HOPCOUNTERROR   -45
#define MPLS_DEC_HOPCOUNTERROR   -46
#define MPLS_ENC_PATHVECERROR    -47
#define MPLS_DEC_PATHVECERROR    -48
#define MPLS_ENC_LBLMSGIDERROR   -49
#define MPLS_DEC_LBLMSGIDERROR   -50
#define MPLS_ENC_HDRTLVERROR     -51
#define MPLS_DEC_HDRTLVERROR     -52
#define MPLS_ENC_FECELEMERROR    -53
#define MPLS_DEC_FECELEMERROR    -54
#define MPLS_ENC_FSPLBLERROR     -55
#define MPLS_DEC_FSPLBLERROR     -56
#define MPLS_ENC_ERHOPERROR      -57
#define MPLS_DEC_ERHOPERROR      -58
#define MPLS_ENC_ERTLVERROR      -59
#define MPLS_DEC_ERTLVERROR      -60
#define MPLS_ENC_ERHOPLENERROR   -61
#define MPLS_DEC_ERHOPLENERROR   -62
#define MPLS_TLVTYPEERROR        -63
#define MPLS_MSGTYPEERROR        -64
#define MPLS_FECERROR            -65
#define MPLS_ENC_TRAFFICERROR    -66
#define MPLS_DEC_TRAFFICERROR    -67
#define MPLS_ENC_LSPIDERROR      -68
#define MPLS_DEC_LSPIDERROR      -69
#define MPLS_ENC_RESCLSERROR     -70
#define MPLS_DEC_RESCLSERROR     -71
#define MPLS_ENC_PREEMPTERROR    -72
#define MPLS_DEC_PREEMPTERROR    -73
#define MPLS_ENC_PINNINGERROR    -74
#define MPLS_DEC_PINNINGERROR    -75
#define MPLS_FLOATTYPEERROR      -76
#define MPLS_FECTLVERROR         -77
#define MPLS_IPV4LENGTHERROR     -78
#define MPLS_ER_HOPSNUMERROR     -79

/**********************************************************************
   LDP header 
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Version                      |         PDU Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         LDP Identifier                        |
   +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**********************************************************************/

typedef struct mplsLdpHeader_s {
  u_short protocolVersion;
  u_short pduLength;            /* length excluding the version and length */
  u_int lsrAddress;             /* IP address assigned to LSR              */
  u_short labelSpace;           /* within LSR                              */

} mplsLdpHeader_t;

/**********************************************************************
   LDP Messages (All LDP messages have the following format:)

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Message Type              |      Message Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                     Mandatory Parameters                      |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                     Optional Parameters                       |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Note: the U flag is ignored for now. There is not check for its value.
**********************************************************************/

typedef struct mplsLdpMsgFlag_s {
  BITFIELDS_ASCENDING_2(u_short uBit:1, u_short msgType:15)
} mplsLdpMsgFlag_t;

typedef struct mplsLdpMsg_s {
  union {
    struct mplsLdpMsgFlag_s flags;
    u_short mark;
  } flags;

  u_short msgLength;            /* msgId + mandatory param + optional param */
  u_int msgId;                  /* used to identify the notification msg    */

} mplsLdpMsg_t;

typedef struct mplsLdpUnknownMsg_s {
  struct mplsLdpMsg_s baseMsg;
  u_char data[MPLS_NOT_MAXSIZE];

} mplsLdpUnknownMsg_t;

/**********************************************************************
   Type-Length-Value Encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|F|        Type               |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                             Value                             |
   ~                                                               ~
   |                                                               |
   |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Note: the decode functions for tlv do not check the values for
      F flag. They check only the value of the U flag; if
      it is set will ignore the tlv and keep processing the message;
      otherwise will ignore the message and return error. Please note 
      that the unknown tlv which is skipped will not be stored anywhere.
**********************************************************************/

typedef struct mplsLdpTlvFlag_s {
  BITFIELDS_ASCENDING_3(u_short uBit:1, u_short fBit:1, u_short tBit:14)
} mplsLdpTlvFlag_t;

typedef struct mplsLdpTlv_s {
  union {
    struct mplsLdpTlvFlag_s flags;
    u_short mark;
  } flags;

  u_short length;               /* length of the value field */

} mplsLdpTlv_t;

/**********************************************************************
  Common Session Parameters TLV

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |U|F| Common Sess Parms (0x0500)|      Length                   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Protocol Version              |      Keep Alive Time          |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |A|D| Reserved  |     PVLim     |      Max PDU Length           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                 Receiver LDP Identifer                        |
       +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                               |
       -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++
***********************************************************************/

typedef struct mplsLdpCspFlag_s {
  BITFIELDS_ASCENDING_4(u_short lad:1, /* 1 = downstream on demand  */
    u_short ld:1,               /* loop detection            */
    u_short res:6,              /* reserved                  */
    u_short pvl:8               /* path vec limit            */
    )
} mplsLdpCspFlag_t;

typedef struct mplsLdpCspTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_short protocolVersion;
  u_short holdTime;             /* proposed keep alive interval */

  union {
    struct mplsLdpCspFlag_s flags;
    u_short mark;
  } flags;

  u_short maxPduLen;
  u_int rcvLsrAddress;
  u_short rcvLsId;

} mplsLdpCspTlv_t;

/*********************************************************************** 
   ATM Label Range Component

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Res  |    Minimum VPI        |      Minimum VCI              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Res  |    Maximum VPI        |      Maximum VCI              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpAtmLblRngFlag_s {
  BITFIELDS_ASCENDING_3(u_int res1:4, /* reserved : 0 on transmision */
    u_int minVpi:12,            /* if <12 bits right justified */
    u_int minVci:16             /* if <16 bits right justified */
    )
  BITFIELDS_ASCENDING_3(u_int res2:4, /* reserved : 0 on transmision */
    u_int maxVpi:12,            /* if <12 bits right justified */
    u_int maxVci:16             /* if <16 bits right justified */
    )
} mplsLdpAtmLblRngFlag_t;

typedef struct mplsLdpAtmLblRng_s {
  union {
    struct mplsLdpAtmLblRngFlag_s flags;
    u_int mark[2];
  } flags;
} mplsLdpAtmLblRng_t;

/*********************************************************************** 
 Flags for ATM Session Parameters TLV and 
	   Frame Relay Session Parameters TLV

 Note: both types of session parameters have the same type of flags;
       use then the same struct
***********************************************************************/

typedef struct mplsLdpSPFlag_s {
  BITFIELDS_ASCENDING_4(u_int mergeType:2, /* merge typ            */
    u_int numLblRng:4,          /* # of label range com */
    u_int dir:1,                /* 0 => bidirectional   */
    u_int res:25)
} mplsLdpSPFlag_t;

/*********************************************************************** 
   ATM Session Parameters TLV

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |U|F|   ATM Sess Parms (0x0501) |      Length                   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | M |   N   |D|                        Reserved                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 ATM Label Range Component 1                   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  ~                                                               ~
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 ATM Label Range Component N                   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpAspTlv_s {
  struct mplsLdpTlv_s baseTlv;
  union {
    struct mplsLdpSPFlag_s flags;
    u_int mark;
  } flags;
  struct mplsLdpAtmLblRng_s lblRngList[MPLS_ATMLBLMAXLEN];

} mplsLdpAspTlv_t;

/***********************************************************************
   Frame Relay Label Range Component

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Reserved    |Len|                     Minimum DLCI            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Reserved        |                     Maximum DLCI            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpFrFlag_s {
  BITFIELDS_ASCENDING_3(u_int res_min:7, u_int len:2, u_int minDlci:23)
  BITFIELDS_ASCENDING_2(u_int res_max:9, u_int maxDlci:23)
} mplsLdpFrFlag_t;

typedef struct mplsLdpFrLblRng_s {
  union {
    struct mplsLdpFrFlag_s flags;
    u_int mark[2];
  } flags;

} mplsLdpFrLblRng_t;

/**********************************************************************
   Frame Relay Session Parameters TLV

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F|   FR Sess Parms (0x0502)  |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | M |   N   |D|                        Reserved                 |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |             Frame Relay Label Range Component 1               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     ~                                                               ~
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |             Frame Relay Label Range Component N               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpFspTlv_s {
  struct mplsLdpTlv_s baseTlv;
  union {
    struct mplsLdpSPFlag_s flags;
    u_int mark;
  } flags;
  struct mplsLdpFrLblRng_s lblRngList[MPLS_FRLBLMAXLEN];

} mplsLdpFspTlv_t;

/***********************************************************************
   Initialization Message Encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Initialization (0x0200)   |      Message Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Common Session Parameters TLV             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Optional Parameters                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpInitMsg_s {
  struct mplsLdpMsg_s baseMsg;
  struct mplsLdpCspTlv_s csp;
  struct mplsLdpAspTlv_s asp;
  struct mplsLdpFspTlv_s fsp;
  u_char cspExists:1;
  u_char aspExists:1;
  u_char fspExists:1;

} mplsLdpInitMsg_t;

/***********************************************************************
   Status Code Encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |E|F|                 Status Data                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/
typedef struct mplsLdpStautsFlag_s {
  BITFIELDS_ASCENDING_3(u_int error:1, /* E bit */
    u_int forward:1,            /* F bit */
    u_int status:30)
} mplsLdpStautsFlag_t;

/***********************************************************************
   Status (TLV) Encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|F| Status (0x0300)           |      Length                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Status Code                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Message Type             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpStatusTlv_s {
  struct mplsLdpTlv_s baseTlv;
  union {
    struct mplsLdpStautsFlag_s flags;
    u_int mark;
  } flags;
  u_int msgId;
  u_short msgType;

} mplsLdpStatusTlv_t;

/***********************************************************************
   Extended Status (TLV) Encoding
***********************************************************************/

typedef struct mplsLdpExStatusTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_int value;                  /* additional info for status */

} mplsLdpExStatusTlv_t;

/***********************************************************************
   Returned PDU (TLV) Encoding
***********************************************************************/

typedef struct mplsLdpRetPduTlv_s {
  struct mplsLdpTlv_s baseTlv;
  struct mplsLdpHeader_s headerTlv;
  u_char data[MPLS_NOT_MAXSIZE];

} mplsLdpRetPduTlv_t;

/***********************************************************************
   Returned MSG (TLV) Encoding
***********************************************************************/

typedef struct mplsLdpRetMsgTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_short msgType;
  u_short msgLength;
  u_char data[MPLS_NOT_MAXSIZE];

} mplsLdpRetMsgTlv_t;

/***********************************************************************
   LSPID Tlv encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F|      LSPID-TLV  (0x0821)  |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |       Reserved                |      Local CRLSP ID           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Ingress LSR Router ID                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpLspIdTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_short res;
  u_short localCrlspId;
  u_int routerId;               /* ingress lsr router id */

} mplsLdpLspIdTlv_t;

/***********************************************************************
   Notification Message Encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Notification (0x0001)     |      Message Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Status (TLV)                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Optional Parameters                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     LSPID TLV (optional for CR-LDP)           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpNotifMsg_s {
  struct mplsLdpMsg_s baseMsg;
  struct mplsLdpStatusTlv_s status;
  struct mplsLdpExStatusTlv_s exStatus; /* extended status tlv */
  struct mplsLdpRetPduTlv_s retPdu; /* returned PDU tlv    */
  struct mplsLdpRetMsgTlv_s retMsg; /* returned MSG tlv    */
  struct mplsLdpLspIdTlv_s lspidTlv; /* lspid tlv           */

  u_char statusTlvExists:1;
  u_char exStatusTlvExists:1;
  u_char retPduTlvExists:1;
  u_char retMsgTlvExists:1;
  u_char lspidTlvExists:1;

} mplsLdpNotifMsg_t;

/***********************************************************************
   Common Hello Parameters Tlv encoding
 
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F| Common Hello Parms(0x0400)|      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Hold Time                |T|R| Reserved                  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/
typedef struct mplsLdpChpFlag_s {
  BITFIELDS_ASCENDING_3(u_short target:1, /* T bit */
    u_short request:1,          /* R bit */
    u_short res:14)
} mplsLdpChpFlag_t;

typedef struct mplsLdpChpTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_short holdTime;
  union {
    struct mplsLdpChpFlag_s flags;
    u_short mark;
  } flags;

} mplsLdpChpTlv_t;

/***********************************************************************
   Transport Address (TLV) Encoding
***********************************************************************/

typedef struct mplsLdpTrAdrTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_int address;

} mplsLdpTrAdrTlv_t;

/***********************************************************************
   Configuration Sequence Number (TLV) Encoding
***********************************************************************/

typedef struct mplsLdpCsnTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_int seqNumber;

} mplsLdpCsnTlv_t;

/***********************************************************************
     Hello message encoding 
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Hello (0x0100)            |      Message Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Common Hello Parameters TLV               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Optional Parameters                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpHelloMsg_s {
  struct mplsLdpMsg_s baseMsg;
  struct mplsLdpChpTlv_s chp;   /* common hello param tlv  */
  struct mplsLdpTrAdrTlv_s trAdr; /* transport address tlv   */
  struct mplsLdpCsnTlv_s csn;   /* configuration seq # tlv */
  u_char chpTlvExists:1;
  u_char trAdrTlvExists:1;
  u_char csnTlvExists:1;

} mplsLdpHelloMsg_t;

/***********************************************************************
   KeepAlive Message encoding
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   KeepAlive (0x0201)        |      Message Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Optional Parameters                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Note: there are no optional param defined for keep alive.
***********************************************************************/

typedef struct mplsLdpKeepAlMsg_s {
  struct mplsLdpMsg_s baseMsg;

} mplsLdpKeepAlMsg_t;

/***********************************************************************
   Address List TLV encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|F| Address List (0x0101)     |      Length                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Address Family            |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   |                                                               |
   |                        Addresses                              |
   ~                                                               ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpAdrTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_short addrFamily;
  u_int address[MPLS_MAXNUMBERADR];

} mplsLdpAdrTlv_t;

/***********************************************************************
   Address (0x0300) / Address Withdraw(0x0301)  message encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Address                   |      Message Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Address List TLV                          |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Optional Parameters                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Note: there are no optional param defined for address message.
***********************************************************************/

typedef struct mplsLdpAdrMsg_s {
  struct mplsLdpMsg_s baseMsg;
  struct mplsLdpAdrTlv_s addressList;
  u_char adrListTlvExists:1;

} mplsLdpAdrMsg_t;

/***********************************************************************
   Wildcard FEC Element encoding
***********************************************************************/

typedef struct mplsLdpWildFec_s {
  u_char type;

} mplsLdpWildFec_t;

/***********************************************************************
   Prefix FEC Element encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Prefix (2)   |     Address Family            |     PreLen    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Prefix                                    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Host Address FEC Element encoding

      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | Host Addr (3) |     Address Family            | Host Addr Len |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Host Addr                                 |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Note: the code handles prefixes and host addresses whose length is 
      less or equal to 4 bytes.

PWid FEC Element encoding  //add by timothy
   
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     PW tlv    |C|           PW type           |PW info Length |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         Group ID                              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           PW ID                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Interface parameters                      |
     |                              "                                |
     |                              "                                |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Interface Parameters Field //add by timothy
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Parameter ID |    Length     |    Variable Length Value      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         Variable Length Value                 |
     |                             "                                 |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

***********************************************************************/

typedef struct mplsLdpAddressFec_s {
  u_char type;
  u_short addressFam;
  u_char preLen;                /* prefix FEC: length of the adr prefix (in bits)
                                   or host adr FEC: length of the host address (in 
                                   bytes) */
  u_int address;

} mplsLdpAddressFec_t;

typedef struct mplsLdpPwidFecIf_s { //add by timothy
  u_char parameter_id;
  u_char length;
  u_short variable_length;
  u_int variable_value[21];
} mplsLdpPwidFecIf_t;

typedef struct mplsLdpPWidFec_s {  //add by timothy
  u_char pw_tlv;
  union {
  BITFIELDS_ASCENDING_2(u_short control_word:1, u_short pw_type:15)
  u_short mark;
  }flags;

  u_char  pw_info_Len;
  u_int group_id;
  u_int pw_id;
  mplsLdpPwidFecIf_t interface_parameters;
 
}mplsLdpPWidFec_t;

/***********************************************************************
   CRLSP FEC Element encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | CR-LSP (4)    |          Reserved                             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpCrlspFec_s {
  u_char type;
  u_char res1;                  /* reserved */
  u_short res2;                 /* reserved */

} mplsLdpCrlspFec_t;

/***********************************************************************
   FEC Tlv encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|F| FEC (0x0100)              |      Length                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        FEC Element 1                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                                                               ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        FEC Element n                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef union mplsFecElement_u {
  struct mplsLdpAddressFec_s addressEl; /* prefix | host adr */
  struct mplsLdpWildFec_s wildcardEl; /* for wilcard fec   */
  struct mplsLdpCrlspFec_s crlspEl; /* CRLSP fec elem    */
  struct mplsLdpPWidFec_s pwidEl; /*Pwid fec element: add by timothy*/

} mplsFecElement_t;

typedef struct mplsLdpFecTlv_s {
  struct mplsLdpTlv_s baseTlv;
  union mplsFecElement_u fecElArray[MPLS_MAXNUMFECELEMENT];
  u_short fecElemTypes[MPLS_MAXNUMFECELEMENT];
  u_char wcElemExists:1;
  u_short numberFecElements;

} mplsLdpFecTlv_t;

/***********************************************************************
   Generic Label Tlv encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|F| Generic Label (0x0200)    |      Length                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Label                                                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpGenLblTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_int label;                  /* 20-bit number in 4 octet field */

} mplsLdpGenLblTlv_t;

/***********************************************************************
   Atm Label Tlv encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|F| ATM Label (0x0201)        |         Length                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Res| V |          VPI          |         VCI                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpAtmLblFlag_s {
  BITFIELDS_ASCENDING_3(u_short res:2, u_short v:2, u_short vpi:12)
} mplsLdpAtmLblFlag_t;

typedef struct mplsLdpAtmLblTlv_s {
  struct mplsLdpTlv_s baseTlv;

  union {
    struct mplsLdpAtmLblFlag_s flags;
    u_short mark;
  } flags;

  u_short vci;

} mplsLdpAtmLblTlv_t;

/***********************************************************************
   Frame Relay Label Tlv encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|F| Frame Relay Label (0x0202)|       Length                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Reserved    |Len|                     DLCI                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpFrLblFlag_s {
  BITFIELDS_ASCENDING_3(u_int res:7, u_int len:2, u_int dlci:23)

} mplsLdpFrLblFlag_t;

typedef struct mplsLdpFrLblTlv_s {
  struct mplsLdpTlv_s baseTlv;

  union {
    struct mplsLdpFrLblFlag_s flags;
    u_int mark;
  } flags;

} mplsLdpFrLblTlv_t;

/***********************************************************************
   Hop Count Tlv encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|F| Hop Count (0x0103)        |      Length                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     HC Value  |
   +-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpHopTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_char hcValue;               /* hop count value */

} mplsLdpHopTlv_t;

/***********************************************************************
   Path Vector Tlv encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|F| Path Vector (0x0104)      |        Length                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            LSR Id 1                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                                                               ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            LSR Id n                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpPathTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_int lsrId[MPLS_MAXHOPSNUMBER];

} mplsLdpPathTlv_t;

/***********************************************************************
   Lbl request message id Tlv encoding
***********************************************************************/

typedef struct mplsLdpLblMsgIdTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_int msgId;

} mplsLdpLblMsgIdTlv_t;

/***********************************************************************
   Preemption Tlv encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F| Preemption-TLV  (0x0820)  |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  SetPrio      | HoldPrio      |      Reserved                 |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpPreemptTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_char setPrio;               /* 0 => most important path */
  u_char holdPrio;              /* 0 => most important path */
  u_short res;

} mplsLdpPreemptTlv_t;

/***********************************************************************
   Resource class Tlv encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F|      ResCls-TLV  (0x0822) |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                             RsCls                             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpResClsTlv_s {
  struct mplsLdpTlv_s baseTlv;
  u_int rsCls;                  /* resource class bit mask */

} mplsLdpResClsTlv_t;

/***********************************************************************
   Lbl return message id Tlv encoding
***********************************************************************/

typedef struct mplsLdpRetMsgIdTlv_s {
  struct mplsLdpTlv_s baseTlv;

} mplsLdpLblRetMsgIdTlv_t;

/***********************************************************************
   ER flag structure which is common to IPV4 and IPV6 ER TLV
***********************************************************************/

typedef struct mplsLdpErIPFlag_s {
  BITFIELDS_ASCENDING_3(u_int l:1, /* 0 => loose hop */
    u_int res:23, u_int preLen:8)
} mplsLdpErIPFlag_t;

/***********************************************************************
   ER flag structure which is common to AS and LSPID ER TLV
***********************************************************************/
typedef struct mplsLdpErFlag_s {
  BITFIELDS_ASCENDING_2(u_short l:1, /* 0 => loose hop */
    u_short res:15)
} mplsLdpErFlag_t;

/***********************************************************************
   Explicit Routing IPv4 Tlv encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F|         0x801             |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |L|      Reserved                               |    PreLen     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    IPv4 Address (4 bytes)                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpErIpv4_s {
  struct mplsLdpTlv_s baseTlv;
  union {
    struct mplsLdpErIPFlag_s flags;
    u_int mark;
  } flags;
  u_int address;

} mplsLdpErIpv4_t;

/***********************************************************************
   Explicit Routing IPv6 Tlv encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F|          0x802            |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |L|             Reserved                        |    PreLen     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  IPV6 address                                 |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  IPV6 address (continued)                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  IPV6 address (continued)                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  IPV6 address (continued)                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpErIpv6_s {
  struct mplsLdpTlv_s baseTlv;
  union {
    struct mplsLdpErIPFlag_s flags;
    u_int mark;
  } flags;
  u_char address[MPLS_IPV6ADRLENGTH];

} mplsLdpErIpv6_t;

/***********************************************************************
   Explicit Routing Autonomous systen number Tlv encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F|          0x803            |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |L|          Reserved           |                AS Number      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpErAs_s {
  struct mplsLdpTlv_s baseTlv;
  union {
    struct mplsLdpErFlag_s flags;
    u_short mark;
  } flags;
  u_short asNumber;

} mplsLdpErAs_t;

/***********************************************************************
   Explicit Routing LSPID Tlv encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F|          0x804            |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |L|          Reserved           |               Local LSPID     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Ingress LSR Router ID                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpErLspId_s {
  struct mplsLdpTlv_s baseTlv;
  union {
    struct mplsLdpErFlag_s flags;
    u_short mark;
  } flags;
  u_short lspid;
  u_int routerId;

} mplsLdpErLspId_t;

/***********************************************************************
   Constraint Routing Tlv encoding

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F|         ER-TLV  (0x0800)  |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          ER-Hop TLV 1                         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          ER-Hop TLV 2                         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ~                          ............                         ~
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          ER-Hop TLV n                         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef union mplsLdpErHop_u {
  struct mplsLdpErIpv4_s erIpv4;
  struct mplsLdpErIpv6_s erIpv6;
  struct mplsLdpErAs_s erAs;
  struct mplsLdpErLspId_s erLspId;

} mplsLdpErHop_t;

typedef struct mplsLdpErTlv_s {
  struct mplsLdpTlv_s baseTlv;
  union mplsLdpErHop_u erHopArray[MPLS_MAX_ER_HOPS];
  u_short erHopTypes[MPLS_MAX_ER_HOPS]; /* need to know the 
                                           types when handle
                                           the union */
  u_short numberErHops;

} mplsLdpErTlv_t;

/***********************************************************************
   Traffic parameters TLV

      0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F| Traf. Param. TLV  (0x0810)|      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Flags     |    Frequency  |     Reserved  |    Weight     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Peak Data Rate (PDR)                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Peak Burst Size (PBS)                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Committed Data Rate (CDR)                  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Committed Burst Size (CBS)                 |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Excess Burst Size (EBS)                    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Flag field:
     +--+--+--+--+--+--+--+--+
     | Res |F6|F5|F4|F3|F2|F1|
     +--+--+--+--+--+--+--+--+
***********************************************************************/

typedef struct mplsLdpTrafficFlag_s {
  BITFIELDS_ASCENDING_7(u_char res:2,
    u_char f6Bit:1,
    u_char f5Bit:1,
    u_char f4Bit:1, u_char f3Bit:1, u_char f2Bit:1, u_char f1Bit:1)
} mplsLdpTrafficFlag_t;

typedef struct mplsLdpTrafficTlv_s {
  struct mplsLdpTlv_s baseTlv;
  union {
    struct mplsLdpTrafficFlag_s flags;
    u_char mark;
  } flags;
  u_char freq;
  u_char res;
  u_char weight;
  union {
    float pdr;
    u_int mark;
  } pdr;
  union {
    float pbs;
    u_int mark;
  } pbs;
  union {
    float cdr;
    u_int mark;
  } cdr;
  union {
    float cbs;
    u_int mark;
  } cbs;
  union {
    float ebs;
    u_int mark;
  } ebs;

} mplsLdpTrafficTlv_t;

/***********************************************************************
   Route pinning TLV

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |U|F|          0x823            |      Length                   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |P|                        Reserved                             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpPinningTlvFlag_s {
  BITFIELDS_ASCENDING_2(u_int pBit:1, /* 1 => route pinning requested */
    u_int res:31)
} mplsLdpPinningTlvFlag_t;

typedef struct mplsLdpPinningTlv_s {
  struct mplsLdpTlv_s baseTlv;
  union {
    struct mplsLdpPinningTlvFlag_s flags;
    u_int mark;
  } flags;
} mplsLdpPinningTlv_t;

/***********************************************************************
   Label Mapping Message encoding
 
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Label Mapping (0x0400)   |      Message Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     FEC TLV                                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Label TLV                                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Label Request Message ID TLV  (mandatory)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     LSPID TLV            (CR-LDP, mandatory)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Traffic  TLV         (CR-LDP, optional)   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpLblMapMsg_s {
  struct mplsLdpMsg_s baseMsg;

  /* FEC tlv */
  struct mplsLdpFecTlv_s fecTlv;

  /* Label TLV */
  struct mplsLdpGenLblTlv_s genLblTlv; /* generic label tlv */
  struct mplsLdpAtmLblTlv_s atmLblTlv; /* atm label tlv     */
  struct mplsLdpFrLblTlv_s frLblTlv; /* fr label tlv      */

  /* Optional parameters */
  struct mplsLdpHopTlv_s hopCountTlv; /* hop count tlv     */
  struct mplsLdpPathTlv_s pathVecTlv; /* path vector tlv   */
  struct mplsLdpLblMsgIdTlv_s lblMsgIdTlv; /* lbl msg id tlv    */
  struct mplsLdpLspIdTlv_s lspidTlv; /* lspid tlv         */
  struct mplsLdpTrafficTlv_s trafficTlv; /* traffic tlv       */

  u_char fecTlvExists:1;
  u_char genLblTlvExists:1;
  u_char atmLblTlvExists:1;
  u_char frLblTlvExists:1;
  u_char hopCountTlvExists:1;
  u_char pathVecTlvExists:1;
  u_char lblMsgIdTlvExists:1;
  u_char lspidTlvExists:1;
  u_char trafficTlvExists:1;

} mplsLdpLblMapMsg_t;

/***********************************************************************
   Label Request Message encoding

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Label Request (0x0401)   |      Message Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     FEC TLV                                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Return Message ID TLV  (mandatory)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     LSPID TLV            (CR-LDP, mandatory)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     ER-TLV               (CR-LDP, optional)   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Traffic  TLV         (CR-LDP, optional)   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Pinning TLV          (CR-LDP, optional)   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Resource Class TLV (CR-LDP, optional)     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Pre-emption  TLV     (CR-LDP, optional)   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpLblReqMsg_s {
  struct mplsLdpMsg_s baseMsg;

  /* FEC tlv */
  struct mplsLdpFecTlv_s fecTlv;

  /* Optional parameters */
  struct mplsLdpHopTlv_s hopCountTlv; /* hop count tlv     */
  struct mplsLdpPathTlv_s pathVecTlv; /* path vector tlv   */

  /* Optional parameters for CR */
  struct mplsLdpRetMsgIdTlv_s lblMsgIdTlv; /* lbl msg id tlv    */
  struct mplsLdpErTlv_s erTlv;  /* constraint rtg tlv */
  struct mplsLdpTrafficTlv_s trafficTlv; /* traffic tlv       */
  struct mplsLdpLspIdTlv_s lspidTlv; /* lspid tlv         */
  struct mplsLdpPinningTlv_s pinningTlv; /* pinning tlv       */
  struct mplsLdpResClsTlv_s resClassTlv; /* resource class tlv */
  struct mplsLdpPreemptTlv_s preemptTlv; /* peemtion tlv      */

  u_char fecTlvExists:1;
  u_char hopCountTlvExists:1;
  u_char pathVecTlvExists:1;
  u_char lblMsgIdTlvExists:1;
  u_char erTlvExists:1;
  u_char trafficTlvExists:1;
  u_char lspidTlvExists:1;
  u_char pinningTlvExists:1;
  u_char recClassTlvExists:1;
  u_char preemptTlvExists:1;

} mplsLdpLblReqMsg_t;

/***********************************************************************

   Label Withdraw Message encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Label Withdraw (0x0402)   |      Message Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     FEC TLV                                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Label TLV (optional)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     LSPID TLV (optional for CR-LDP)           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Label Release Message encoding

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Label Release (0x0403)   |      Message Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     FEC TLV                                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Label TLV (optional)                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     LSPID TLV (optional for CR-LDP)           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
Note: the Label Withdraw Message encoding and the Label Release Message enc
      look very much the same. I will create only one type of struct for 
      both message types.
      The Label Withdraw Message and Label Release Message can optionally
      carry LSPID TLV.
***********************************************************************/

typedef struct mplsLdpLbl_W_R_Msg_s {
  struct mplsLdpMsg_s baseMsg;

  /* FEC tlv */
  struct mplsLdpFecTlv_s fecTlv;

  /* Label TLV */
  struct mplsLdpGenLblTlv_s genLblTlv; /* generic label tlv */
  struct mplsLdpAtmLblTlv_s atmLblTlv; /* atm label tlv     */
  struct mplsLdpFrLblTlv_s frLblTlv; /* fr label tlv      */
  struct mplsLdpLspIdTlv_s lspidTlv; /* lspid tlv         */

  u_char fecTlvExists:1;
  u_char genLblTlvExists:1;
  u_char atmLblTlvExists:1;
  u_char frLblTlvExists:1;
  u_char lspidTlvExists:1;

} mplsLdpLbl_W_R_Msg_t;

/***********************************************************************
   Label Abort Request Message encoding
 
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |U|   Label Abort Req (0x0404) |      Message Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Message ID                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     FEC TLV                                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Label Request Message ID TLV                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
***********************************************************************/

typedef struct mplsLdpLblAbortMsg_s {
  struct mplsLdpMsg_s baseMsg;

  struct mplsLdpFecTlv_s fecTlv; /* fec tlv        */
  struct mplsLdpLblMsgIdTlv_s lblMsgIdTlv; /* lbl msg id tlv */

  u_char fecTlvExists:1;
  u_char lblMsgIdTlvExists:1;

} mplsLdpLblAbortMsg_t;

/***********************************************************************
 *
 *          Function declarations
 *
 *  Note: Encode functions return the length of the data which was encoded. 
 *        The first argument (which is a pointer to the structure which
 *        contains the data to be encoded) is not modified in the encode functions
 *        which encode the messages and message headers. All the other encode 
 *        fuctions modify the content of the structures to be encoded (tlvs, 
 *        message parameters, etc). 
 *
 *	  Decode functions for tlv return the length of the value. 
 */

int Mpls_encodeLdpMsgHeader(mplsLdpHeader_t *, u_char *, int);
int Mpls_decodeLdpMsgHeader(mplsLdpHeader_t *, u_char *, int);
int Mpls_encodeLdpAtmLblRng(mplsLdpAtmLblRng_t *, u_char *, int);
int Mpls_decodeLdpAtmLblRng(mplsLdpAtmLblRng_t *, u_char *, int);
int Mpls_encodeLdpAsp(mplsLdpAspTlv_t *, u_char *, int);
int Mpls_decodeLdpAsp(mplsLdpAspTlv_t *, u_char *, int);
int Mpls_encodeLdpTlv(mplsLdpTlv_t *, u_char *, int);
int Mpls_decodeLdpTlv(mplsLdpTlv_t *, u_char *, int);
int Mpls_encodeLdpInitMsg(mplsLdpInitMsg_t *, u_char *, int);
int Mpls_decodeLdpInitMsg(mplsLdpInitMsg_t *, u_char *, int);
int Mpls_encodeLdpCsp(mplsLdpCspTlv_t *, u_char *, int);
int Mpls_decodeLdpCsp(mplsLdpCspTlv_t *, u_char *, int);
int Mpls_encodeLdpBaseMsg(mplsLdpMsg_t *, u_char *, int);
int Mpls_decodeLdpBaseMsg(mplsLdpMsg_t *, u_char *, int);
int Mpls_encodeLdpFrLblRng(mplsLdpFrLblRng_t *, u_char *, int);
int Mpls_decodeLdpFrLblRng(mplsLdpFrLblRng_t *, u_char *, int);
int Mpls_encodeLdpFsp(mplsLdpFspTlv_t *, u_char *, int);
int Mpls_decodeLdpFsp(mplsLdpFspTlv_t *, u_char *, int);
int Mpls_encodeLdpNotMsg(mplsLdpNotifMsg_t *, u_char *, int);
int Mpls_decodeLdpNotMsg(mplsLdpNotifMsg_t *, u_char *, int);
int Mpls_encodeLdpStatus(mplsLdpStatusTlv_t *, u_char *, int);
int Mpls_decodeLdpStatus(mplsLdpStatusTlv_t *, u_char *, int);
int Mpls_encodeLdpExStatus(mplsLdpExStatusTlv_t *, u_char *, int);
int Mpls_decodeLdpExStatus(mplsLdpExStatusTlv_t *, u_char *, int);
int Mpls_encodeLdpRetPdu(mplsLdpRetPduTlv_t *, u_char *, int);
int Mpls_decodeLdpRetPdu(mplsLdpRetPduTlv_t *, u_char *, int, u_short);
int Mpls_encodeLdpRetMsg(mplsLdpRetMsgTlv_t *, u_char *, int);
int Mpls_decodeLdpRetMsg(mplsLdpRetMsgTlv_t *, u_char *, int, u_short);
int Mpls_encodeLdpHelloMsg(mplsLdpHelloMsg_t *, u_char *, int);
int Mpls_decodeLdpHelloMsg(mplsLdpHelloMsg_t *, u_char *, int);
int Mpls_encodeLdpChp(mplsLdpChpTlv_t *, u_char *, int);
int Mpls_decodeLdpChp(mplsLdpChpTlv_t *, u_char *, int);
int Mpls_encodeLdpCsn(mplsLdpCsnTlv_t *, u_char *, int);
int Mpls_decodeLdpCsn(mplsLdpCsnTlv_t *, u_char *, int);
int Mpls_encodeLdpTrAdr(mplsLdpTrAdrTlv_t *, u_char *, int);
int Mpls_decodeLdpTrAdr(mplsLdpTrAdrTlv_t *, u_char *, int);
int Mpls_encodeLdpKeepAliveMsg(mplsLdpKeepAlMsg_t *, u_char *, int);
int Mpls_decodeLdpKeepAliveMsg(mplsLdpKeepAlMsg_t *, u_char *, int);
int Mpls_encodeLdpAdrTlv(mplsLdpAdrTlv_t *, u_char *, int);
int Mpls_decodeLdpAdrTlv(mplsLdpAdrTlv_t *, u_char *, int, u_short);
int Mpls_encodeLdpAdrMsg(mplsLdpAdrMsg_t *, u_char *, int);
int Mpls_decodeLdpAdrMsg(mplsLdpAdrMsg_t *, u_char *, int);
int Mpls_encodeLdpFecTlv(mplsLdpFecTlv_t *, u_char *, int);
int Mpls_decodeLdpFecTlv(mplsLdpFecTlv_t *, u_char *, int, u_short);
int Mpls_encodeLdpGenLblTlv(mplsLdpGenLblTlv_t *, u_char *, int);
int Mpls_decodeLdpGenLblTlv(mplsLdpGenLblTlv_t *, u_char *, int);
int Mpls_encodeLdpAtmLblTlv(mplsLdpAtmLblTlv_t *, u_char *, int);
int Mpls_decodeLdpAtmLblTlv(mplsLdpAtmLblTlv_t *, u_char *, int);
int Mpls_encodeLdpFrLblTlv(mplsLdpFrLblTlv_t *, u_char *, int);
int Mpls_decodeLdpFrLblTlv(mplsLdpFrLblTlv_t *, u_char *, int);
int Mpls_encodeLdpHopTlv(mplsLdpHopTlv_t *, u_char *, int);
int Mpls_decodeLdpHopTlv(mplsLdpHopTlv_t *, u_char *, int);
int Mpls_encodeLdpLblMsgIdTlv(mplsLdpLblMsgIdTlv_t *, u_char *, int);
int Mpls_decodeLdpLblMsgIdTlv(mplsLdpLblMsgIdTlv_t *, u_char *, int);
int Mpls_encodeLdpPathVectorTlv(mplsLdpPathTlv_t *, u_char *, int);
int Mpls_decodeLdpPathVectorTlv(mplsLdpPathTlv_t *, u_char *, int, u_short);
int Mpls_encodeLdpLblMapMsg(mplsLdpLblMapMsg_t *, u_char *, int);
int Mpls_decodeLdpLblMapMsg(mplsLdpLblMapMsg_t *, u_char *, int);
int Mpls_encodeLdpFecAdrEl(mplsFecElement_t *, u_char *, int, u_char);
int Mpls_decodeLdpFecAdrEl(mplsFecElement_t *, u_char *, int, u_char);
int Mpls_encodeLdpLblRetMsgIdTlv(mplsLdpLblRetMsgIdTlv_t *, u_char *, int);
int Mpls_decodeLdpLblRetMsgIdTlv(mplsLdpLblRetMsgIdTlv_t *, u_char *, int);
int Mpls_encodeLdpLbl_W_R_Msg(mplsLdpLbl_W_R_Msg_t *, u_char *, int);
int Mpls_decodeLdpLbl_W_R_Msg(mplsLdpLbl_W_R_Msg_t *, u_char *, int);
int Mpls_encodeLdpERTlv(mplsLdpErTlv_t *, u_char *, int);
int Mpls_decodeLdpERTlv(mplsLdpErTlv_t *, u_char *, int, u_short);
int Mpls_encodeLdpErHop(mplsLdpErHop_t *, u_char *, int, u_short);
int Mpls_decodeLdpErHop(mplsLdpErHop_t *, u_char *, int, u_short *);
int Mpls_encodeLdpTrafficTlv(mplsLdpTrafficTlv_t *, u_char *, int);
int Mpls_decodeLdpTrafficTlv(mplsLdpTrafficTlv_t *, u_char *, int, u_short);
int Mpls_encodeLdpLblReqMsg(mplsLdpLblReqMsg_t *, u_char *, int);
int Mpls_decodeLdpLblReqMsg(mplsLdpLblReqMsg_t *, u_char *, int);
int Mpls_encodeLdpPreemptTlv(mplsLdpPreemptTlv_t *, u_char *, int);
int Mpls_decodeLdpPreemptTlv(mplsLdpPreemptTlv_t *, u_char *, int);
int Mpls_encodeLdpLspIdTlv(mplsLdpLspIdTlv_t *, u_char *, int);
int Mpls_decodeLdpLspIdTlv(mplsLdpLspIdTlv_t *, u_char *, int);
int Mpls_encodeLdpResClsTlv(mplsLdpResClsTlv_t *, u_char *, int);
int Mpls_decodeLdpResClsTlv(mplsLdpResClsTlv_t *, u_char *, int);
int Mpls_encodeLdpPinningTlv(mplsLdpPinningTlv_t *, u_char *, int);
int Mpls_decodeLdpPinningTlv(mplsLdpPinningTlv_t *, u_char *, int);
int Mpls_encodeLdpLblAbortMsg(mplsLdpLblAbortMsg_t *, u_char *, int);
int Mpls_decodeLdpLblAbortMsg(mplsLdpLblAbortMsg_t *, u_char *, int);

/*
 *   DEBUG function declarations
 */

void printTlv(mpls_instance_handle handle, mplsLdpTlv_t *);
void printHeader(mpls_instance_handle handle, mplsLdpHeader_t *);
void printCspFlags(mpls_instance_handle handle, mplsLdpCspFlag_t *);
void printCspFlagsPerByte(mpls_instance_handle handle, u_short *);
void printCspTlv(mpls_instance_handle handle, mplsLdpCspTlv_t *);
void printAspFlags(mpls_instance_handle handle, mplsLdpSPFlag_t *);
void printAspFlagsPerByte(mpls_instance_handle handle, u_int *);
void printAspTlv(mpls_instance_handle handle, mplsLdpAspTlv_t *);
void printFspFlags(mpls_instance_handle handle, mplsLdpSPFlag_t *);
void printFspTlv(mpls_instance_handle handle, mplsLdpFspTlv_t *);
void printRetMsgTlv(mpls_instance_handle handle, mplsLdpRetMsgTlv_t *);
void printRetPduTlv(mpls_instance_handle handle, mplsLdpRetPduTlv_t *);
void printExStatusTlv(mpls_instance_handle handle, mplsLdpExStatusTlv_t *);
void printStatusTlv(mpls_instance_handle handle, mplsLdpStatusTlv_t *);
void printCsnTlv(mpls_instance_handle handle, mplsLdpCsnTlv_t *);
void printTrAdrTlv(mpls_instance_handle handle, mplsLdpTrAdrTlv_t *);
void printChpTlv(mpls_instance_handle handle, mplsLdpChpTlv_t *);
void printAdrListTlv(mpls_instance_handle handle, mplsLdpAdrTlv_t *);
void printFecListTlv(mpls_instance_handle handle, mplsLdpFecTlv_t *);
void printLblMsgIdTlv(mpls_instance_handle handle, mplsLdpLblMsgIdTlv_t *);
void printPathVecTlv(mpls_instance_handle handle, mplsLdpPathTlv_t *);
void printHopTlv(mpls_instance_handle handle, mplsLdpHopTlv_t *);
void printFrLblTlv(mpls_instance_handle handle, mplsLdpFrLblTlv_t *);
void printAtmLblTlv(mpls_instance_handle handle, mplsLdpAtmLblTlv_t *);
void printGenLblTlv(mpls_instance_handle handle, mplsLdpGenLblTlv_t *);
void printErFlags(mpls_instance_handle handle, mplsLdpErFlag_t *);
void printErIPFlags(mpls_instance_handle handle, mplsLdpErIPFlag_t *);
void printErTlv(mpls_instance_handle handle, mplsLdpErTlv_t *);
void printTrafficTlv(mpls_instance_handle handle, mplsLdpTrafficTlv_t *);
void printAtmLabel(mpls_instance_handle handle, mplsLdpAtmLblRng_t *, int);
void printFspLabel(mpls_instance_handle handle, mplsLdpFrLblRng_t *, int);
void printErHop(mpls_instance_handle handle, mplsLdpErHop_t *, u_short);
void printPreemptTlv(mpls_instance_handle handle, mplsLdpPreemptTlv_t *);
void printLspIdTlv(mpls_instance_handle handle, mplsLdpLspIdTlv_t *);
void printResClsTlv(mpls_instance_handle handle, mplsLdpResClsTlv_t *);
void printPinningTlv(mpls_instance_handle handle, mplsLdpPinningTlv_t *);

void printInitMsg(mpls_instance_handle handle, mplsLdpInitMsg_t *);
void printHelloMsg(mpls_instance_handle handle, mplsLdpHelloMsg_t *);
void printNotMsg(mpls_instance_handle handle, mplsLdpNotifMsg_t *);
void printKeepAliveMsg(mpls_instance_handle handle, mplsLdpKeepAlMsg_t *);
void printAddressMsg(mpls_instance_handle handle, mplsLdpAdrMsg_t *);
void printLlbMapMsg(mpls_instance_handle handle, mplsLdpLblMapMsg_t *);
void printLlbReqMsg(mpls_instance_handle handle, mplsLdpLblReqMsg_t *);
void printLbl_W_R_Msg(mpls_instance_handle handle, mplsLdpLbl_W_R_Msg_t *);
void printLlbAbortMsg(mpls_instance_handle handle, mplsLdpLblAbortMsg_t *);

int converAsciiToHex(u_char *, int, u_char *);
int converHexToAscii(u_char *, int, u_char *);

#endif /* _LDP_MPLS_H_ */
