/*****************************************************************************
 * MPLS
 *      An implementation of the MPLS (MultiProtocol Label
 *      Switching Architecture) for Linux.
 *
 * _THIS_FILE_
 *	mplsadm : User space Application
 *
 *   (c) 1999-2004   James Leu        <jleu@mindspring.com>

 * Authors:
 *          James Leu        <jleu@mindspring.com>
 *          Ramon Casellas   <casellas@infres.enst.fr>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 * TODO:
 * 	Decouple checking parameters and commit changes.
 * 	No IOCTL should be done if there is a single incorrect parameter
 *
 * Changes:
 *	20031130 RCAS:
 *		o Get a spoon and a fork for this spagetthi code.
 *		o Cleanup
 *	20031212 RCAS:
 *		o Comment parts of the code.
 *	20031220 RCAS:
 *		o Looks like Change MTU was missing
 *	20040110 RCAS:
 ****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/mpls.h>
#include <sys/ioctl.h>
#include <linux/atm.h>
#include <asm/types.h>
#include <errno.h>
int fd = 0;
char mplsadm_verbose = 1;




#define VERBOSE(f, a...) \
{ \
        if (mplsadm_verbose) {\
                fprintf(stderr,"MPLSADM %s:%d:%s: ", \
                        __FILE__, __LINE__, __FUNCTION__); \
                fprintf(stderr,f, ##a); \
        }\
}





#define IOCTL_VERBOSE(RES) \
	{\
	if ((RES)) {\
		switch errno {\
			case EBADF: \
				VERBOSE("d is not a valid descriptor.\n");\
				break;\
			case EFAULT: \
				VERBOSE("argp references an inaccessible memory area.\n");\
				break;\
	             	case ENOTTY: \
				VERBOSE("d is not associated with a character special device,");\
		            	VERBOSE("or the specified request does not apply to the kind of object");  \
				VERBOSE("that the descriptor d references.\n");\
				break;\
			case EINVAL:\
				VERBOSE("Request or argp is not valid.\n");\
				break;\
		}\
	}}


		

static
void usage() 
{
	fprintf(stderr,"usage: mplsadm [ADBUdhvT:L:I:O:i:o:2:]\n\n");
	fprintf(stderr,"-A add modifier\n");
	fprintf(stderr,"-B bind modifier\n");
	fprintf(stderr,"-D delete modifier\n");
	fprintf(stderr,"-U unbind modifier\n");
	fprintf(stderr,"-d toggle debug\n");
	fprintf(stderr,"-h this message\n");
	fprintf(stderr,"-v mplsadm_verbose info\n");
	fprintf(stderr,"-p <proto> ILM protocol\n");
	fprintf(stderr,"-m <mtu> NHLFE mtu\n");
	fprintf(stderr,"-F flush all ILMs and NHLFEs\n");
	fprintf(stderr,"-T <tunnel name>:<dest addr>\n");
	fprintf(stderr,"-L <interface name>:<label space> set the label space for"
			" an interface (-1 disables)\n");
	fprintf(stderr,"-I <gen|atm|fr>:<label>:<label space> create|delete an"
			" incoming label\n");
	fprintf(stderr,"-O <key> (create with a key of 0)\n");
	fprintf(stderr,"-i <opcode:opcode_data>+\n");
	fprintf(stderr,"-o <opcode:opcode_data>+\n");
	fprintf(stderr,"-V output the MPLS kernel version used at compile time\n");
	fprintf(stderr,"\n\n");
}



/**
 *	resolve_it - Resolve the address of a host
 *	@host: host
 **/

unsigned int resolve_it (char *host) 
{
	unsigned int result = -1;
	struct hostent *hp;

	if (isdigit(host[0])) {
		result = inet_addr(host);
	} else {
		hp = gethostbyname(host);
		if (hp) {
			memcpy(&result,hp->h_addr,sizeof(unsigned int));
		}
	}
	return result;
}


/**
 *	parse_args - Parse argument string, separated by ':'	
 *	@argc: number of char* elems in argv to fill in
 *	@argv: array of char* elems
 *	@args: input string: "foo:bar:gee"
 **/

int parse_args (int argc,char **argv,char *args) 
{
	int i = 1;

	argv[0] = strtok(args,":");
	while((argv[i] = strtok(NULL,":"))) {
		i++;
		if (i > (argc - 1)) {
			return -i;
		}
	}
	return i;
}


/**
 *	parse_nh_info - Parse Next Hop Information
 *	@mni: struct to fill in
 *	@arg: argument array, from "ipv4:a.b.c.d"
 *	@start: where to start in array
 *
 **/

int parse_nh_info (struct mpls_nexthop_info *mni,char **arg, int start) 
{
	struct ifreq ifr;
	int result;
	int len;
	int i = 0;

	VERBOSE("%s\n",arg[start]);
	VERBOSE("%s\n",arg[start+2]);
	len = strlen(arg[start]);
	i++;
	if (len > 0 && len < IFNAMSIZ) {
		/* Set the Interface name in ifr.ifr_name */
		memset(&ifr,0,sizeof(struct ifreq));
		strncpy(ifr.ifr_name,arg[start],IFNAMSIZ);
		/* Resolve its interface index */
		result = ioctl(fd,SIOCGIFINDEX,&ifr);
		if (result) {
			fprintf(stderr,"Unable to resolve ifindex for %s\n",ifr.ifr_name);
			exit(0);
		}
		/* Update the passed struct with interface index */
		mni->mni_if = ifr.ifr_ifindex;
		memset(&mni->mni_addr,0,sizeof(struct sockaddr));
		/* Only IPv4 is supported now */
		if (arg[start+1] && !strcmp(arg[start+1],"ipv4")) {
			/* Resolve its INET address */ 
			struct sockaddr_in sin;
			memset(&sin,0,sizeof(sin));
			i++;
			VERBOSE("Nexthop protocol: ipv4\n");
			sin.sin_addr.s_addr = resolve_it(arg[start+2]);
			sin.sin_family      = AF_INET;
			i++;
			/* Update the passed struct with address */
			memcpy(&mni->mni_addr,&sin,sizeof(struct sockaddr));
		}
	}
	return i;
}



/**
 *	fill_label - Parse Label Information 
 *	@lbl: struct to fill in
 *	@args: argument array, from "ipv4:a.b.c.d"
 *	@start: where to start in array
 *
 **/

int fill_label(struct mpls_label *lbl,char **args,int start) 
{
	int result = 0;

	VERBOSE("Label type: %s\n",args[start]);
	/* ATM Label ? */
	if(!strncmp(args[start],"atm",3)) {
		char *vpi_str,*vci_str;
		int vpi,vci;

		vpi_str = strtok(args[start+1],"/");
		vci_str = strtok(NULL,"\0");
		if (vpi_str && vci_str) {
			vpi = atoi(vpi_str);
			vci = atoi(vci_str);
			if(vpi > -1 && vpi < ATM_MAX_VPI && vci > -1 && vci < ATM_MAX_VCI) {
				lbl->ml_type = MPLS_LABEL_ATM;
				lbl->u.ml_atm.mla_vpi = vpi;
				lbl->u.ml_atm.mla_vci = vci;
			}
		}
		result = 1;
	/* GENERIC Label */
	} else if(!strncmp(args[start],"gen",3)) {
		lbl->ml_type = MPLS_LABEL_GEN;
		lbl->u.ml_gen = atol(args[start+1]);
		result = 1;
	/* Frame Relay Label */
	} else if(!strncmp(args[start],"fr",2)) {
		lbl->ml_type = MPLS_LABEL_FR;
		lbl->u.ml_fr = atol(args[start+1]);
		result = 1;
	/* Key (implementation dep. */
	} else  if(!strncmp(args[start],"key",3)) {
		lbl->ml_type  = MPLS_LABEL_KEY;
		lbl->u.ml_key = strtol(args[start+1],NULL,0);
		result = 1;
	}
	return result;
}




/**
 *	fill_instructions - Parse Instructions Opcodes and Params. 
 *	@mir: struct to fill in
 *	@arg: argument array, "set:ath0:..."
 *	@start: where to start in array
 *	@num: count
 *
 * 	RCAS: This function really needs to be rewritten :)) 
 *	I'll do it tommorrow, promised! and split, like kernel code!!
 **/

int fill_instructions(
	struct mpls_instr_req *mir, 
	char** arg,
	int start,
	int num) 
{
	struct ifreq ifr;
	int length = 0;
	int result;
	int i;

	for(i=start;i<(num+start);i++) {
		VERBOSE("Instruction: %s\n",arg[i]);
		if(!strncmp("pop",arg[i],3)) {
			mir->mir_instr[length].mir_opcode = MPLS_OP_POP;
		} else if(!strncmp("peek",arg[i],4)) {
			mir->mir_instr[length].mir_opcode = MPLS_OP_PEEK;
		} else if(!strncmp("push",arg[i],4)) {
			i++;
			mir->mir_instr[length].mir_opcode = MPLS_OP_PUSH;
			if (!(result = fill_label(&(mir->mir_instr[length].mir_data.push),arg,i))) {
				fprintf(stderr,"Error while parsing label\n");
				exit(-1);
			}
			i += result;
		} else if(!strncmp("dlv",arg[i],3)) {
			mir->mir_instr[length].mir_opcode = MPLS_OP_DLV;
		} else if(!strncmp("fwd",arg[i],3)) {
			mir->mir_instr[length].mir_opcode = MPLS_OP_FWD;
			i++;
			if(!(result = fill_label(&(mir->mir_instr[length].mir_data.fwd),
							arg,i))) {
				fprintf(stderr,"Error while parsing label\n");
				exit(-1);
			}
			i += result;
		} else if(!strncmp("nffwd",arg[i],4)) {
			unsigned short nf;
			unsigned int out,mask;
			mir->mir_instr[length].mir_opcode = MPLS_OP_NF_FWD;

			memset(&mir->mir_instr[length].mir_data.nf_fwd,0,
					sizeof(mir->mir_instr[length].mir_data.nf_fwd));

			i++;
			mask = strtol(arg[i++],NULL,0);
			if (mask > MPLS_NFMARK_NUM) {
				fprintf(stderr,"Mask for nffwd is too large, ");
				fprintf(stderr,"must be less then 0x%02x\n",MPLS_NFMARK_NUM);
			}
			mir->mir_instr[length].mir_data.nf_fwd.nf_mask = mask;

			while((i < (num + start)) && isdigit(arg[i][0])) {
				nf = strtol(arg[i++],NULL,0);
				VERBOSE("NFMARK: %s ",arg[i]);
				VERBOSE("%d\n",nf);
				if((i < (num + start)) && isdigit(arg[i][0])) {
					VERBOSE("OUT: %s ",arg[i]);
					out = strtol(arg[i++],NULL,0);
					VERBOSE("%08x\n",out);
					mir->mir_instr[length].mir_data.nf_fwd.nf_key[nf & mask] = out;
				}
			}
			i--;
		} else if(!strncmp("dsfwd",arg[i],4)) {
			unsigned char ds;
			unsigned char mask;
			unsigned int out;
			mir->mir_instr[length].mir_opcode = MPLS_OP_DS_FWD;

			memset(&mir->mir_instr[length].mir_data.ds_fwd,0,
					sizeof(mir->mir_instr[length].mir_data.ds_fwd));

			i++;
			mask = strtol(arg[i++],NULL,0);
			if (mask > MPLS_DSMARK_NUM) {
				fprintf(stderr,"Mask for dsfwd is too large, ");
				fprintf(stderr,"must be less then 0x%02x\n",MPLS_DSMARK_NUM);
			}
			mir->mir_instr[length].mir_data.ds_fwd.df_mask = mask;

			while((i < (num + start)) && isdigit(arg[i][0])) {
				VERBOSE("DSMARK: %s ",arg[i]);
				ds = strtol(arg[i++],NULL,0);
				VERBOSE("%d\n",ds);

				if((i < (num + start)) && isdigit(arg[i][0])) {
					VERBOSE("OUT: %s ",arg[i]);
					out = strtol(arg[i++],NULL,0);
					VERBOSE("%08x\n",out);
					mir->mir_instr[length].mir_data.ds_fwd.df_key[ds & mask] = out;
				}
			}
			i--;
		} else if(!strncmp("expfwd",arg[i],5)) {
			unsigned char exp;
			unsigned int out;

			mir->mir_instr[length].mir_opcode = MPLS_OP_EXP_FWD;

			memset(&mir->mir_instr[length].mir_data.exp_fwd,0,
					sizeof(mir->mir_instr[length].mir_data.exp_fwd));

			i++;

			while((i < (num + start)) && isdigit(arg[i][0])) {
				VERBOSE("EXP: %s ",arg[i]);
				exp = strtol(arg[i++],NULL,0);
				if (exp > 0x7) {
					fprintf(stderr,"EXP for expfwd is too large, must be less then 8\n");
				}
				VERBOSE("%d\n",exp);

				if((i < (num + start)) && isdigit(arg[i][0])) {
					VERBOSE("OUT: %s ",arg[i]);
					out = strtol(arg[i++],NULL,0);
					VERBOSE("%08x\n",out);
					mir->mir_instr[length].mir_data.ds_fwd.df_key[exp] = out;
				}
			}
			i--;
		} else if(!strncmp("set_ds",arg[i],6)) {
			mir->mir_instr[length].mir_opcode = MPLS_OP_SET_DS;
			mir->mir_instr[length].mir_data.set_ds = strtol(arg[++i],NULL,0);

		} else if(!strncmp("set_tc",arg[i],6)) {
			mir->mir_instr[length].mir_opcode = MPLS_OP_SET_TC;
			mir->mir_instr[length].mir_data.set_tc = strtol(arg[++i],NULL,0);

		} else if(!strncmp("set_exp",arg[i],7)) {
			mir->mir_instr[length].mir_opcode = MPLS_OP_SET_EXP;
			mir->mir_instr[length].mir_data.set_exp = strtol(arg[++i],NULL,0);
			
		} else if(!strncmp("set",arg[i],3)) {

			mir->mir_instr[length].mir_opcode = MPLS_OP_SET;
			i++;

			if(mir->mir_direction == MPLS_OUT) {
				i+=parse_nh_info(&(mir->mir_instr[length].mir_data.set),arg,i);
			} else {
				memset(&ifr,0,sizeof(struct ifreq));
				strcpy(ifr.ifr_name,arg[i]);
				if((result = ioctl(fd,SIOCGIFINDEX,&ifr)) != 0) {
					perror("SET-SIOCGIFINDEX");
					exit(result);
				}
				mir->mir_instr[length].mir_data.set.mni_if = ifr.ifr_ifindex;
			}
		} else if(!strncmp("exp2tc",arg[i],5)) {
			unsigned char exp;
			unsigned short tc;

			mir->mir_instr[length].mir_opcode = MPLS_OP_EXP2TC;

			memset(&mir->mir_instr[length].mir_data.exp2tc,0xFF,
					sizeof(mir->mir_instr[length].mir_data.exp2tc));

			i++;

			while((i < (num + start)) && isdigit(arg[i][0])) {
				VERBOSE("EXP: %s ",arg[i]);
				exp = strtol(arg[i++],NULL,0);
				if (exp > 0x7) {
					fprintf(stderr,"EXP for exp2tc is too large, must be less then 8\n");
				}
				VERBOSE("%d\n",exp);

				if((i < (num + start)) && isdigit(arg[i][0])) {
					VERBOSE("TC: %s ",arg[i]);
					tc = strtol(arg[i++],NULL,0);
					VERBOSE("%d\n",tc);
					mir->mir_instr[length].mir_data.exp2tc.e2t[exp] = tc;
				}
			}
			i--;
		} else if(!strncmp("exp2ds",arg[i],5)) {
			unsigned char exp;
			unsigned char ds;

			mir->mir_instr[length].mir_opcode = MPLS_OP_EXP2DS;

			memset(&mir->mir_instr[length].mir_data.exp2ds,0xFF,
					sizeof(mir->mir_instr[length].mir_data.exp2ds));

			i++;

			while((i < (num + start)) && isdigit(arg[i][0])) {
				VERBOSE("EXP: %s ",arg[i]);
				exp = strtol(arg[i++],NULL,0);
				if (exp > 0x7) {
					fprintf(stderr,"EXP for exp2tc is too large, must be less then 8\n");
				}
				VERBOSE("%d\n",exp);

				if((i < (num + start)) && isdigit(arg[i][0])) {
					VERBOSE("DS: %s ",arg[i]);
					ds = strtol(arg[i++],NULL,0);
					VERBOSE("%d\n",ds);
					mir->mir_instr[length].mir_data.exp2ds.e2d[exp&0x7] = ds;
				}
			}
			i--;
		} else if(!strncmp("nf2exp",arg[i],5)) {
			unsigned char exp;
			unsigned short nf;
			unsigned short mask;

			mir->mir_instr[length].mir_opcode = MPLS_OP_NF2EXP;

			memset(&mir->mir_instr[length].mir_data.nf2exp,0xFF,
					sizeof(mir->mir_instr[length].mir_data.nf2exp));

			i++;

			mask = strtol(arg[i++],NULL,0);
			if (mask > MPLS_NFMARK_NUM) {
				fprintf(stderr,"Mask for nf2exp is too large, ");
				fprintf(stderr,"must be less then 0x%02x\n",MPLS_NFMARK_NUM);
			}
			mir->mir_instr[length].mir_data.nf2exp.n2e_mask = mask;

			while((i < (num + start)) && isdigit(arg[i][0])) {
				VERBOSE("NF: %s ",arg[i]);
				nf = strtol(arg[i++],NULL,0);
				VERBOSE("%d\n",nf);

				if((i < (num + start)) && isdigit(arg[i][0])) {
					VERBOSE("EXP: %s ",arg[i]);
					exp = strtol(arg[i++],NULL,0);
					if (exp > 0x7) {
						fprintf(stderr,"EXP for nf2exp is too large, must be less then 8\n");
					}
					VERBOSE("%d\n",exp);
					mir->mir_instr[length].mir_data.nf2exp.n2e[nf & mask] = exp;
				}
			}
			i--;
		} else if(!strncmp("tc2exp",arg[i],5)) {
			unsigned char exp;
			unsigned short tc;
			unsigned short mask;

			mir->mir_instr[length].mir_opcode = MPLS_OP_TC2EXP;

			memset(&mir->mir_instr[length].mir_data.tc2exp,0xFF,
					sizeof(mir->mir_instr[length].mir_data.tc2exp));

			i++;

			mask = strtol(arg[i++],NULL,0);
			if (mask > MPLS_TCINDEX_NUM) {
				fprintf(stderr,"Mask for tc2exp is too large, ");
				fprintf(stderr,"must be less then 0x%02x\n",MPLS_TCINDEX_NUM);
			}
			mir->mir_instr[length].mir_data.tc2exp.t2e_mask = mask;

			while((i < (num + start)) && isdigit(arg[i][0])) {
				VERBOSE("TC: %s ",arg[i]);
				tc = strtol(arg[i++],NULL,0);
				VERBOSE("%d\n",tc);

				if((i < (num + start)) && isdigit(arg[i][0])) {
					VERBOSE("EXP: %s ",arg[i]);
					exp = strtol(arg[i++],NULL,0);
					if (exp > 0x7) {
						fprintf(stderr,"EXP for tc2exp is too large, must be less then 8\n");
					}
					VERBOSE("%d\n",exp);
					mir->mir_instr[length].mir_data.tc2exp.t2e[tc & mask] = exp;
				}
			}
			i--;
		} else if(!strncmp("ds2exp",arg[i],5)) {
			unsigned char exp;
			unsigned char ds;
			unsigned char mask;

			mir->mir_instr[length].mir_opcode = MPLS_OP_DS2EXP;

			memset(&mir->mir_instr[length].mir_data.ds2exp,0xFF,
					sizeof(mir->mir_instr[length].mir_data.ds2exp));

			i++;

			mask = strtol(arg[i++],NULL,0);
			if (mask > MPLS_DSMARK_NUM) {
				fprintf(stderr,"Mask for ds2exp is too large, ");
				fprintf(stderr,"must be less then 0x%02x\n",MPLS_DSMARK_NUM);
			}
			mir->mir_instr[length].mir_data.ds2exp.d2e_mask = mask;

			while((i < (num + start)) && isdigit(arg[i][0])) {
				VERBOSE("DS: %s ",arg[i]);
				ds = strtol(arg[i++],NULL,0);
				VERBOSE("%d\n",ds);

				if((i < (num + start)) && isdigit(arg[i][0])) {
					VERBOSE("EXP: %s ",arg[i]);
					exp = strtol(arg[i++],NULL,0);
					if (exp > 0x7) {
						fprintf(stderr,"EXP for nf2exp is too large, must be less then 8\n");
					}
					VERBOSE("%d\n",exp);
					mir->mir_instr[length].mir_data.ds2exp.d2e[ds & mask] = exp;
				}
			}
			i--;
		} else {
			fprintf(stderr,"unknown %s\n",arg[i]);
			continue;
		}
		length++;
	}
	mir->mir_instr_length = length;

	VERBOSE("Length: %d\n",length);
	return 0;
}




int
#ifdef	MPLSADM_MAIN_CLI
main
#else	//MPLSADM_MAIN_CLI
mpls_action
#endif	//MPLSADM_MAIN_CLI
(int argc, char **argv) {
	int add_olabel=0;
	struct mpls_instr_req mir_req;
	struct mpls_labelspace_req  mls_req;
	struct mpls_out_label_req   mol_req;
	struct mpls_in_label_req    mil_req;
	struct mpls_xconnect_req    mx_req;

	struct ifreq ifr;

	char *in_instr_str = NULL;
	char *out_instr_str = NULL;
	char *in_label_str = NULL;
	char *out_str = NULL;
	char *tunnel_str = NULL;
	char *proto_str = NULL;
	char *mtu_str = NULL;
	char *label_space_str = NULL;
	char *larg[1024];
	int result = -1;
	int num = 0;
	int opt;

	char delete = 0;
	char add = 0;
	char bind = 0;
	char unbind = 0;
	char debug = 0;
	char flush = 0;

	fd = socket(AF_INET,SOCK_DGRAM,0);
	if(fd < 0) {
		perror("Socket");
		exit(fd);
	}

	memset(&mil_req,0,sizeof(struct mpls_in_label_req));
	memset(&mls_req,0,sizeof(struct mpls_labelspace_req));
	memset(&mol_req,0,sizeof(struct mpls_out_label_req));
	memset(&mx_req, 0,sizeof(struct mpls_xconnect_req));
	memset(&mir_req,0,sizeof(struct mpls_instr_req));

optind = 1;
	while((opt = getopt(argc,argv,"ADBUdhvFT:L:I:O:i:o:m:p:V")) != EOF) {
		switch(opt) {
			case 'A':
				add = 1;
				break;
			case 'B':
				bind = 1;
				break;
			case 'D':
				delete = 1;
				break;
			case 'U':
				unbind = 1;
				break;
			case 'd':
				debug = 1;
				break;
			case 'v':
				mplsadm_verbose = 1;
				break;
			case 'F':
				flush = 1;
				break;
			case 'p':
				proto_str = optarg;
				break;
			case 'm':
				mtu_str = optarg;
				break;
			case 'I':
				in_label_str = optarg;
				VERBOSE("In label input: %s\n",in_label_str);
				break;
			case 'L':
				label_space_str = optarg;
				VERBOSE("Label Space input: %s\n",label_space_str);
				break;
			case 'i':
				in_instr_str = optarg;
				VERBOSE("In instr input: %s\n",in_instr_str);
				break;
			case 'o':
				out_instr_str = optarg;
				VERBOSE("Out instr input: %s\n",out_instr_str);
				break;
			case 'O':
				out_str = optarg;
				VERBOSE("Out segment input: %s\n",out_str);
				break;
			case 'T':
				tunnel_str = optarg;
				VERBOSE("Tunnel input: %s\n",tunnel_str);
				break;
			case 'V':
				fprintf(stdout, "\n\tMPLS version %d.%d%d%d\n\n",
						(MPLS_LINUX_VERSION >> 24) & 0xFF,
						(MPLS_LINUX_VERSION >> 16) & 0xFF,
						(MPLS_LINUX_VERSION >> 8) & 0xFF,
						MPLS_LINUX_VERSION & 0xFF);
				break;
			case 'h':
			default:
				usage();
				exit(result);
				break;
		}
	}
#if 0
	if(debug) {
		result = ioctl(fd,SIOCMPLSDEBUG,&ifr);
		IOCTL_VERBOSE(result);
		perror("Debug");
	}
#endif

	if (flush) {
		result = ioctl(fd,SIOCMPLSILMFLUSH,&ifr);
		IOCTL_VERBOSE(result);
		result = ioctl(fd,SIOCMPLSNHLFEFLUSH,&ifr);
		IOCTL_VERBOSE(result);
		perror("Flush");
		/* RCAS: Do not Let the user shoot himself in the foot */
		return (result);
	}

	/* -L  "label_space_str"*/
	if (label_space_str) {
		int len = 0;
		num = parse_args(1024,larg,label_space_str);
		len = strlen(larg[0]);
		if (num != 2) {
			perror("Label Space: not enough parameters.");
			exit(0);
		}
		/* larg[0]="eth0" larg[1]="0" */
		VERBOSE("Interface: %s Label Space: %s\n",larg[0],larg[1]);
		if (len > 0 && len < IFNAMSIZ) {
			memset(&ifr,0,sizeof(struct ifreq));
			strcpy(ifr.ifr_name,larg[0]);
			result = ioctl(fd,SIOCGIFINDEX,&ifr);
			IOCTL_VERBOSE(result);
			if (result) {
				perror("SIOCGIFINDEX");
				exit(result);
			}
			mls_req.mls_ifindex    = ifr.ifr_ifindex;
			mls_req.mls_labelspace = atoi(larg[1]);
			result = ioctl(fd,SIOCSLABELSPACEMPLS,&mls_req);
			IOCTL_VERBOSE(result);
		}
		/* RCAS: Do not Let the user shoot himself in the foot */
		perror("Set Labelspace");
		return (result);
	}





	/* "-T larg[0]" */
	if (tunnel_str) {
		num = parse_args(1024,larg,tunnel_str);
		/* -A -T larg[0] */
		if (add && num == 1) {
			strncpy(ifr.ifr_name,larg[0],IFNAMSIZ);
			result = ioctl(fd,SIOCMPLSTUNNELADD,&ifr);
			if (bind) {
				result = ioctl(fd,SIOCGIFINDEX,&ifr);
			}
		} else if((delete && num == 1) || (bind && num == 1)) {
			strcpy(ifr.ifr_name,larg[0]);
			if(delete) {
				result = ioctl(fd,SIOCMPLSTUNNELDEL,&ifr);
			} else {
				result = ioctl(fd,SIOCGIFINDEX,&ifr);
			}
		} else {
			fprintf(stderr,"Tunnel: wrong number of paramters(%d)\n",num);
			fprintf(stderr,"Tunnel: -A -T <name>\n");
			fprintf(stderr,"Tunnel: -D -T <name>\n");
			fprintf(stderr,"Tunnel: -B ... -T <name>\n");
			tunnel_str = NULL;
		}
	}


	/* "-I in_label_str" */
	if (in_label_str) {
		num = parse_args(1024,larg,in_label_str);
		if (num != 3) {
			fprintf(stderr,"In Label: wrong number of paramters(%d)\n",num);
			in_label_str = NULL;
			perror("Invalid argument");
			exit(0);
		}
		fill_label(&mil_req.mil_label,larg,0);
		if (mil_req.mil_label.ml_type == MPLS_LABEL_KEY) {
			fprintf(stderr,"In labels cannot be specified via 'key'");
			exit(-1);
		}
		mil_req.mil_label.ml_index = atoi(larg[2]);
		if(delete) {
			result = ioctl(fd,SIOCMPLSILMDEL,&mil_req);
			perror("In Label del");
		} else if(add) {
			result = ioctl(fd,SIOCMPLSILMADD,&mil_req);
			perror("In Label add");
		}
	}

	/* "-O <key>|0" */
	if (out_str) {
		/* Set label type to key */
		mol_req.mol_label.ml_type  = MPLS_LABEL_KEY;
		/* Obtain numeric key */
		mol_req.mol_label.u.ml_key = strtol(out_str,NULL,0);

		if (delete) {
			result = ioctl(fd,SIOCMPLSNHLFEDEL,&mol_req);
			printf("Key: 0x%08x\n",mol_req.mol_label.u.ml_key);
			perror("Out Segment del");
		} else if(add) {
			result = ioctl(fd,SIOCMPLSNHLFEADD,&mol_req);
			printf("Key: 0x%08x\n",mol_req.mol_label.u.ml_key);
			perror("Out Segment add");
			add_olabel=mol_req.mol_label.u.ml_key;
		}
	}

	/*****************************************
	 * Set input Instructions 
	 *****************************************/
	/* -I "in_label_str" -i "in_instr_str" */
	if (in_label_str && in_instr_str) {
		num = parse_args(1024,larg,in_instr_str);
		if(num < 1) {
			fprintf(stderr,"In Instr: wrong number of parameters(%d)\n",num);
			exit(0);
		}

		mir_req.mir_direction = MPLS_IN;
		result = fill_instructions(&mir_req,larg,0,num);
		if (result >= 0) {
			memcpy(&mir_req.mir_label,&mil_req.mil_label,sizeof(struct mpls_label));
			mir_req.mir_index = mil_req.mil_label.ml_index;
			result = ioctl(fd,SIOCSMPLSININSTR,&mir_req);
		}
		perror("In Instr");
	}

	/*****************************************
	 * Set output Instructions 
	 *****************************************/
	/* -0 "out_label_str" -o "out_instr_str" */
	if (out_instr_str && out_str) {
		num = parse_args(1024,larg,out_instr_str);
		if(num < 1) {
			fprintf(stderr,"Out Instr: wrong number of parameters(%d)\n",num);
			exit(0);
		}
		mir_req.mir_direction = MPLS_OUT;
		result = fill_instructions(&mir_req,larg,0,num);
		if (result >= 0) {
			memcpy(&mir_req.mir_label,&mol_req.mol_label,sizeof(struct mpls_label));
			result = ioctl(fd,SIOCSMPLSOUTINSTR,&mir_req);
		}
		perror("Out Instr");
	}

	/*****************************************
	 * [DEPRECATED: Set/Unset a Tunnel Moi 
	 *****************************************/
	/* -T "tunnel_str" -O "out_str" */
	if (out_str && tunnel_str) {
		/* RCAS 20040124 -B|-U -T is deprecated*/
		if (bind || unbind){ 
char*	inf_name=NULL;
int	label_key=0;
int	i;
for(i=0;i<argc;i++)
{
	if( strcmp("-O", argv[i]) == 0)
	{
		if( i+1 < argc )
		label_key=atoi(argv[i+1]);
	}
	else
	if( strcmp("-T", argv[i]) == 0)
	{
		if( i+1 < argc )
		inf_name=argv[i+1];
	}
}
if(label_key)
{
	char	buffer[1024];
	snprintf(buffer, sizeof(buffer),
"echo %d > /sys/mpls/mpls_tunnel/mtp-%s/nhlfe", label_key, inf_name);
	result = system(buffer);
}
else
{
			printf(
			"Using %s to bind/unbind MOIs to tunnels is deprecated in 2.6 \n"
			"Use: \n"
			"echo \"<key>|0\" > /sys/mpls/mpls_tunnel/mtp-%s/moi\n " 
			"to bind / unbind a MOI to a tunnel\n", argv[0],tunnel_str);
			result = -1;
			errno  = EINVAL;
			perror("Bind/Unbind MOI");
			exit(-1);
}
		}
	}

	/*****************************************
	 * Establish a Cross-Connect
	 * Requires both an incoming label and an
	 * outgoing key.
	 * and either
	 * bind && not delete
	 * unbind && not add
	 *****************************************/
	/* -O "out_str" -I "in_label_str" */
	if (out_str && in_label_str) {
		/* Do not allow -i "int_instr_str" */
		if (in_instr_str) {
			fprintf(stderr,"Bind In2Out: not at same time as In Instr\n");
			exit (0);
		}
		memcpy(&mx_req.mx_in, &mil_req.mil_label,sizeof(struct mpls_label));
		memcpy(&mx_req.mx_out,&mol_req.mol_label,sizeof(struct mpls_label));

		if (bind && !delete) {
			result = ioctl(fd,SIOCMPLSXCADD,&mx_req);
			perror("Bind In2Out add");
		} else if(unbind && !add) {
			result = ioctl(fd,SIOCMPLSXCDEL,&mx_req);
			perror("Bind In2Out del");
		} else {
			fprintf(stderr,"Bind In2Out: No modifer specified\n");
			exit(0);
		}
	}

#if 0
	/*****************************************
	 * Set layer 3 protocol for incoming labels 
	 * Only valid for incoming labels 
	 * and no delete.
	 *****************************************/
	/* -I "in_label_str" -p "proto_str" */
	if (proto_str && in_label_str && !delete) {
		mil_req.mil_proto = strtol(proto_str,NULL,0);
		result = ioctl(fd,SIOCMPLSILMSETPROTO,&mil_req);
		perror("Set ILM Proto");
	}

	/*****************************************
	 * Set ougoing MTU 
	 * Only valid for outgoing labels (keys) 
	 * and no delete.
	 * RCAS BUG: It should be SIOCMPLSNHLFESETMTU
	 *****************************************/
	/* -O "out_str" -m "mtu_str" */ 
	if (out_str && mtu_str && !delete) {
		mol_req.mol_mtu = strtol(mtu_str,NULL,0);
		/* RCAS 20040124: SIOCMPLSNHLFESETMTU" */
		result = ioctl(fd,SIOCMPLSNHLFESETMTU,&mol_req);
		perror("Set NHLFE MTU");
	}
#endif

if(add_olabel)
	result=add_olabel;
	return result;
}
