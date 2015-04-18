/*
 * mpls.c		"mpls" utility frontend.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <asm/types.h>
#include <linux/if_ether.h>
#include <linux/gen_stats.h>
#include <linux/mpls.h>
#include <linux/socket.h>
#include <sys/ioctl.h>
#include <linux/genetlink.h>

#include "SNAPSHOT.h"
#include "utils.h"

int show_stats = 0;
int show_details = 0;
int show_raw = 0;
int resolve_hosts = 0;
int add_olabel_key=0;//add by here

struct rtnl_handle rth1;	/* RTNL for NHLFE Adds */
struct rtnl_handle rth2;	/* RTNL for all other MPLS entity actions */

extern int do_mplsmonitor(int argc, char **argv);
int print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);
char mpls_table[1024]={0};
char print_label_buf[50]={0};
char print_instructions_buf[150]={0};
char print_address_buf[50]={0};
char print_mpls_stats_buf[50]={0};


//static void usage(void)
static int usage(void)
{
	fprintf(stderr, "Usage: mpls ilm CMD label LABEL labelspace NUMBER [proto PROTO | instructions INSTR]\n");
	fprintf(stderr, "       mpls nhlfe CMD key KEY [mtu MTU propagate_ttl | instructions INSTR]\n");
	fprintf(stderr, "       mpls xc CMD ilm_label LABEL ilm_labelspace NUMBER nhlfe_key KEY\n");
	fprintf(stderr, "       mpls labelspace set dev NAME labelspace NUMBER\n");
	fprintf(stderr, "       mpls labelspace set dev NAME labelspace -1\n");
	fprintf(stderr, "       mpls tunnel CMD dev NAME nhlfe KEY\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "       mpls ilm show [label LABEL labelspace NUMBER]\n");
	fprintf(stderr, "       mpls nhlfe show [key KEY]\n");
	fprintf(stderr, "       mpls xc show [ilm_label LABEL ilm_labelspace NUMBER]\n");
	fprintf(stderr, "       mpls labelspace show [dev NAME]\n");
	fprintf(stderr, "       mpls monitor ...\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where:\n");
	fprintf(stderr, "CMD    := add | del | change\n");
	fprintf(stderr, "NUMBER := 0 .. 255\n");
	fprintf(stderr, "TYPE   := gen | atm | fr\n");
	fprintf(stderr, "VALUE  := 16 .. 1048575 | <VPI>/<VCI> | 16 .. 1023\n");
	fprintf(stderr, "LABEL  := TYPE VALUE\n");
	fprintf(stderr, "KEY    := 0 for add | previously returned key\n");
	fprintf(stderr, "NAME   := network device name (i.e. eth0)\n");
	fprintf(stderr, "PROTO  := ipv4 | ipv6\n");
	fprintf(stderr, "ADDR   := ipv6 or ipv4 address\n");
	fprintf(stderr, "NH     := nexthop NAME [none|packet|PROTO ADDR]\n");
	fprintf(stderr, "FWD    := forward KEY\n");
	fprintf(stderr, "PUSH   := push LABEL\n");
	fprintf(stderr, "INSTR  := NH | PUSH | pop | deliver | peek | FWD |\n");
	fprintf(stderr, "	  set-dscp <DSCP> | set-exp <EXP> |\n");
	fprintf(stderr, "	  set-tcindex <TCINDEX> | set-rx-if <NAME>\n");
	fprintf(stderr, "	  forward <KEY> | expfwd <EXP> <KEY> ... |\n");
	fprintf(stderr, "	  exp2tc <EXP> <TCINDEX> ... | exp2ds <EXP> <DSCP> ... |\n");
	fprintf(stderr, "	  nffwd <MASK> [ <NFMARK> <KEY> ... ] |\n");
	fprintf(stderr, "	  nf2exp <MASK> [ <NFMARK> <EXP> ... ] |\n");
	fprintf(stderr, "	  tc2exp <MASK> [ <TCINDEX> <EXP> ... ] |\n");
	fprintf(stderr, "	  ds2exp <MASK> [ <DSCP> <EXP> ... ] |\n");
	fprintf(stderr, "	  dsfwd <MASK> [ <DSCP> <KEY> ... ]\n");
	fprintf(stderr, "\n");
	//exit(-1);
	return -1;
}

int mpls_list(int cmd,int argc, char **argv);

int mpls_table_list(int argc, char **argv)
{
	if (argc <= 0) {
		mpls_list(MPLS_CMD_GETNHLFE,0,NULL);
		mpls_list(MPLS_CMD_GETILM,0,NULL);
		mpls_list(MPLS_CMD_GETXC,0,NULL);
		mpls_list(MPLS_CMD_GETLABELSPACE,0,NULL);
	}
	return 0;
}

//void
//mpls_parse_label (struct mpls_label *label, int *pargc, char ***pargv) {
int
mpls_parse_label (struct mpls_label *label, int *pargc, char ***pargv) {
	unsigned int l1, l2;
	char *value;
	int argc = *pargc;
	char **argv = *pargv;

	if (strncmp(*argv, "fr", 2) == 0) {
		label->ml_type = MPLS_LABEL_FR;
	} else if (strncmp(*argv, "atm", 3) == 0) {
		label->ml_type = MPLS_LABEL_ATM;
	} else if (strncmp(*argv, "gen", 3) == 0) {
		label->ml_type = MPLS_LABEL_GEN;
	} else {
		invarg(*argv, "invalid mpls label type");
	}

	NEXT_ARG();
	value = *argv;

	switch (label->ml_type) {
		case MPLS_LABEL_GEN:
			if (get_unsigned(&l1, value, 0) || l1 > 1048575)
				invarg(value, "invalid label value");
			label->u.ml_gen = l1;
			break;
		case MPLS_LABEL_ATM:
			if (sscanf(value, "%u/%d", &l1, &l2) != 2)
				invarg(value, "invalid label value");
			label->u.ml_atm.mla_vpi = l1;
			label->u.ml_atm.mla_vci = l2;
		case MPLS_LABEL_FR:
			if (get_unsigned(&l1, value, 0) || l1 > 1023)
				invarg(value, "invalid label value");
			label->u.ml_fr = l1;
		default:
			fprintf(stderr, "Invalid label type!\n");
			//exit(-1);
			return -1;
	}
	*pargc = argc;
	*pargv = argv;
}

void
mpls_parse_instr(struct mpls_instr_req *instr, int *pargc, char ***pargv,
	int direction) {
	int argc = *pargc;
	char **argv = *pargv;
	int c = 0;

	while (argc > 0) {
		if (strcmp(*argv, "nexthop") == 0) {
			NEXT_ARG();
			inet_prefix addr;
			instr->mir_instr[c].mir_opcode = MPLS_OP_SET;
			instr->mir_instr[c].mir_set.mni_if =
				ll_name_to_index(*argv);
			NEXT_ARG();
			if (strcmp(*argv, "ipv4") == 0) {
				struct sockaddr_in *sin = (struct sockaddr_in*)
					&instr->mir_instr[c].mir_set.mni_addr;
				NEXT_ARG();
				get_addr(&addr, *argv, AF_INET);
				sin->sin_family = AF_INET;
				memcpy(&sin->sin_addr, &addr.data,
					addr.bytelen);
			} else if (strcmp(*argv, "ipv6") == 0) {
				struct sockaddr_in6 *sin6=(struct sockaddr_in6*)
					&instr->mir_instr[c].mir_set.mni_addr;
				NEXT_ARG();
				get_addr(&addr, *argv, AF_INET6);
				sin6->sin6_family = AF_INET6;
				memcpy(&sin6->sin6_addr, &addr.data,
					addr.bytelen);
			} else if (strcmp(*argv, "packet") == 0) {
				struct sockaddr *s =
					&instr->mir_instr[c].mir_set.mni_addr;
				s->sa_family = AF_PACKET;
			} else if (strcmp(*argv, "none") == 0) {
				struct sockaddr *s =
					&instr->mir_instr[c].mir_set.mni_addr;
				memset(s, 0, sizeof(struct sockaddr));
				continue;
			} else {
				invarg(*argv, "invalid nexthop type");
			}
		} else if (strcmp(*argv, "push") == 0) {
			NEXT_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_PUSH;
			*pargc = argc; *pargv = argv;
			mpls_parse_label(&instr->mir_instr[c].mir_push,
				pargc, pargv);
			argc = *pargc; argv = *pargv;
		} else if (strcmp(*argv, "forward") == 0) {
			__u32 key;
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid key");
			instr->mir_instr[c].mir_fwd.ml_type = MPLS_LABEL_KEY;
			instr->mir_instr[c].mir_fwd.u.ml_key = key;
			instr->mir_instr[c].mir_opcode = MPLS_OP_FWD;
		} else if (strcmp(*argv, "pop") == 0) {
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			instr->mir_instr[c].mir_opcode = MPLS_OP_POP;
		} else if (strcmp(*argv, "peek") == 0) {
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			instr->mir_instr[c].mir_opcode = MPLS_OP_PEEK;
		} else if (strcmp(*argv, "deliver") == 0) {
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			instr->mir_instr[c].mir_opcode = MPLS_OP_DLV;
		} else if (strcmp(*argv, "set-dscp") == 0) {
			__u32 dscp;
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			NEXT_ARG();
			if (get_unsigned(&dscp, *argv, 0))
				invarg(*argv, "invalid DSCP");
			instr->mir_instr[c].mir_opcode = MPLS_OP_SET_DS;
			instr->mir_instr[c].mir_set_ds = dscp;
		} else if (strcmp(*argv, "set-tcindex") == 0) {
			__u32 tcindex;
			NEXT_ARG();
			if (get_unsigned(&tcindex, *argv, 0))
				invarg(*argv, "invalid TCINDEX");
			instr->mir_instr[c].mir_opcode = MPLS_OP_SET_TC;
			instr->mir_instr[c].mir_set_tc = tcindex;
		} else if (strcmp(*argv, "set-exp") == 0) {
			__u32 exp;
			NEXT_ARG();
			if (get_unsigned(&exp, *argv, 0))
				invarg(*argv, "invalid EXP");
			instr->mir_instr[c].mir_opcode = MPLS_OP_SET_EXP;
			instr->mir_instr[c].mir_set_exp = exp;
		} else if (strcmp(*argv, "set-rx-if") == 0) {
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			NEXT_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_SET_RX;
			instr->mir_instr[c].mir_set_rx =ll_name_to_index(*argv);
		} else if (strcmp(*argv, "expfwd") == 0) {
			int done = 0;
			unsigned int exp;
			unsigned int key;
			do {
				NEXT_ARG();
				if (get_unsigned(&exp, *argv, 0)) {
					done = 1;
					break;
				}
				NEXT_ARG();
				if (get_unsigned(&key, *argv, 0)) {
					done = 1;
					break;
				}
				instr->mir_instr[c].mir_exp_fwd.ef_key[exp] = key;
			} while (!done);
			PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_EXP_FWD;
		} else if (strcmp(*argv, "exp2tc") == 0) {
			int done = 0;
			unsigned int exp;
			unsigned int tcindex;
			do {
				NEXT_ARG();
				if (get_unsigned(&exp, *argv, 0)) {
					done = 1;
					break;
				}
				NEXT_ARG();
				if (get_unsigned(&tcindex, *argv, 0)) {
					done = 1;
					break;
				}
				instr->mir_instr[c].mir_exp2tc.e2t[exp] =
									tcindex;
			} while (!done);
			PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_EXP2TC;
		} else if (strcmp(*argv, "exp2ds") == 0) {
			int done = 0;
			unsigned int exp;
			unsigned int dscp;
			if (direction == MPLS_OUT)
				invarg(*argv, "invalid NHLFE instruction");
			do {
				NEXT_ARG();
				if (get_unsigned(&exp, *argv, 0)) {
					done = 1;
					break;
				}
				NEXT_ARG();
				if (get_unsigned(&dscp, *argv, 0)) {
					done = 1;
					break;
				}
				instr->mir_instr[c].mir_exp2ds.e2d[exp] = dscp;
			} while (!done);
			PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_EXP2DS;
		} else if (strcmp(*argv, "nffwd") == 0) {
			int done = 0;
			unsigned int nfmark;
			unsigned int key;
			unsigned int mask;
			NEXT_ARG();
			if (!get_unsigned(&mask, *argv, 0)) {
				instr->mir_instr[c].mir_nf_fwd.nf_mask = mask;
				do {
					NEXT_ARG();
					if (get_unsigned(&nfmark, *argv, 0)) {
						done = 1;
						break;
					}
					NEXT_ARG();
					if (get_unsigned(&key, *argv, 0)) {
						done = 1;
						break;
					}
					instr->mir_instr[c].mir_nf_fwd.nf_key[nfmark] = key;
				} while (!done);
			}
			PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_NF_FWD;
		} else if (strcmp(*argv, "nf2exp") == 0) {
			int done = 0;
			unsigned int nfmark;
			unsigned int exp;
			unsigned int mask;
			NEXT_ARG();
			if (!get_unsigned(&mask, *argv, 0)) {
				instr->mir_instr[c].mir_nf2exp.n2e_mask = mask;
				do {
					NEXT_ARG();
					if (get_unsigned(&nfmark, *argv, 0)) {
						done = 1;
						break;
					}
					NEXT_ARG();
					if (get_unsigned(&exp, *argv, 0)) {
						done = 1;
						break;
					}
					instr->mir_instr[c].mir_nf2exp.n2e[nfmark] = exp;
				} while (!done);
			}
			PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_NF2EXP;
		} else if (strcmp(*argv, "tc2exp") == 0) {
			int done = 0;
			unsigned int tcindex;
			unsigned int exp;
			unsigned int mask;
			NEXT_ARG();
			if (!get_unsigned(&mask, *argv, 0)) {
				instr->mir_instr[c].mir_tc2exp.t2e_mask = mask;
				do {
					NEXT_ARG();
					if (get_unsigned(&tcindex, *argv, 0)) {
						done = 1;
						break;
					}
					NEXT_ARG();
					if (get_unsigned(&exp, *argv, 0)) {
						done = 1;
						break;
					}
					instr->mir_instr[c].mir_tc2exp.t2e[tcindex] = exp;
				} while (!done);
			}
			PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_TC2EXP;
		} else if (strcmp(*argv, "ds2exp") == 0) {
			int done = 0;
			unsigned int dscp;
			unsigned int exp;
			unsigned int mask;
			if (direction == MPLS_IN)
				invarg(*argv, "invalid ILM instruction");
			NEXT_ARG();
			if (!get_unsigned(&mask, *argv, 0)) {
				instr->mir_instr[c].mir_ds2exp.d2e_mask = mask;
				do {
					NEXT_ARG();
					if (get_unsigned(&dscp, *argv, 0)) {
						done = 1;
						break;
					}
					NEXT_ARG();
					if (get_unsigned(&exp, *argv, 0)) {
						done = 1;
						break;
					}
					instr->mir_instr[c].mir_ds2exp.d2e[dscp] = exp;
				} while (!done);
			}
			PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_DS2EXP;
		} else if (strcmp(*argv, "dsfwd") == 0) {
			int done = 0;
			unsigned int dscp;
			unsigned int key;
			unsigned int mask;
			NEXT_ARG();
			if (!get_unsigned(&mask, *argv, 0)) {
				instr->mir_instr[c].mir_ds_fwd.df_mask = mask;
				do {
					NEXT_ARG();
					if (get_unsigned(&dscp, *argv, 0)) {
						done = 1;
						break;
					}
					NEXT_ARG();
					if (get_unsigned(&key, *argv, 0)) {
						done = 1;
						break;
					}
					instr->mir_instr[c].mir_ds_fwd.df_key[dscp] = key;
				} while (!done);
			}
			PREV_ARG();
			instr->mir_instr[c].mir_opcode = MPLS_OP_DS_FWD;
		} else {
			invarg(*argv, "invalid mpls instruction");
		}
		argc--; argv++; c++;
	}
	instr->mir_instr_length = c;
	instr->mir_direction = direction;

	*pargc = argc;
	*pargv = argv;
}

int
mpls_ilm_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr		n;
		char			buf[4096];
	} req;
	struct mpls_in_label_req	mil;
	struct mpls_instr_req		instr;

	memset(&req, 0, sizeof(req));
	memset(&mil, 0, sizeof(mil));
	memset(&instr, 0, sizeof(instr));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = PF_MPLS;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	mil.mil_proto = AF_INET;

	while (argc > 0) {
		if (strcmp(*argv, "labelspace") == 0) {
			__u32 ls;
			NEXT_ARG();
			if (get_unsigned(&ls, *argv, 0) || ls > 255)
				invarg(*argv, "invalid labelspace");
			mil.mil_label.ml_index = ls;
		} else if (strcmp(*argv, "label") == 0) {
			NEXT_ARG();
			mpls_parse_label(&mil.mil_label, &argc, &argv);
		} else if (strcmp(*argv, "proto") == 0) {
			NEXT_ARG();
			if (strncmp(*argv, "ipv4", 4) == 0) {
				mil.mil_proto = AF_INET;
			} else if (strncmp(*argv, "ipv6", 4) == 0) {
				mil.mil_proto = AF_INET6;
			} else if (strncmp(*argv, "packet", 6) == 0) {
				mil.mil_proto = AF_PACKET;
			} else {
				invarg(*argv, "invalid ilm proto");
			}
			mil.mil_change_flag |= MPLS_CHANGE_PROTO;
		} else if (strcmp(*argv, "instructions") == 0) {
			NEXT_ARG();
			mpls_parse_instr(&instr, &argc, &argv, MPLS_IN);
			mil.mil_change_flag |= MPLS_CHANGE_INSTR;
		} else {
			invarg(*argv, "invalid ilm argument");
		}
		argc--; argv++;
	}

	if (!mil.mil_label.ml_type) {
		fprintf(stderr, "you must specify a label value\n");
		//exit(1);
		return 1;
	}

	addattr_l(&req.n, sizeof(req), MPLS_ATTR_ILM, &mil, sizeof(mil));
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_INSTR, &instr, sizeof(instr));

	if (rtnl_talk(&rth2, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		return 2;
		//exit(2);

	return 0;
}

int
mpls_nhlfe_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr		n;
		char			buf[4096];
	} req;
	struct mpls_out_label_req 	mol;
	struct mpls_instr_req 		instr;

	memset(&req, 0, sizeof(req));
	memset(&mol, 0, sizeof(mol));
	memset(&instr, 0, sizeof(instr));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = PF_MPLS;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {
		if (strcmp(*argv, "key") == 0) {
			__u32 key;
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid key");
			mol.mol_label.u.ml_key = key;
			mol.mol_label.ml_type = MPLS_LABEL_KEY;
		} else if (strcmp(*argv, "mtu") == 0) {
			__u32 mtu;
			NEXT_ARG();
			if (get_unsigned(&mtu, *argv, 0))
				invarg(*argv, "invalid mtu");
			mol.mol_mtu = mtu;
			mol.mol_change_flag |= MPLS_CHANGE_MTU;
		} else if (strcmp(*argv, "no_propagate_ttl") == 0) {
			mol.mol_propagate_ttl = 0;
			mol.mol_change_flag |= MPLS_CHANGE_PROP_TTL;
		} else if (strcmp(*argv, "propagate_ttl") == 0) {
			mol.mol_propagate_ttl = 1;
			mol.mol_change_flag |= MPLS_CHANGE_PROP_TTL;
		} else if (strcmp(*argv, "instructions") == 0) {
			NEXT_ARG();
			mpls_parse_instr(&instr, &argc, &argv, MPLS_OUT);
			mol.mol_change_flag |= MPLS_CHANGE_INSTR;
		} else {
			usage();
		}
		argc--; argv++;
	}

	addattr_l(&req.n, sizeof(req), MPLS_ATTR_NHLFE, &mol, sizeof(mol));
	addattr_l(&req.n, sizeof(req), MPLS_ATTR_INSTR, &instr, sizeof(instr));

	if (flags & NLM_F_CREATE) {
		if (rtnl_talk(&rth1, &req.n, 0, 0, &req.n, NULL, NULL) < 0)
			return 2;
			//exit(2);

		print_mpls(NULL, &req.n, stdout);
	} else {
		if (rtnl_talk(&rth2, &req.n, 0, 0, NULL, NULL, NULL) < 0)
			return 2;
			//exit(2);
	}

	return 0;
}

int
mpls_xc_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr 	n;
		char			buf[4096];
	} req;
	struct mpls_xconnect_req	xc;

	memset(&req, 0, sizeof(req));
	memset(&xc, 0, sizeof(xc));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = PF_MPLS;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {

		if (strcmp(*argv, "ilm_labelspace") == 0) {
			__u32 ls;
			NEXT_ARG();
			if (get_unsigned(&ls, *argv, 0) || ls > 255)
				invarg(*argv, "invalid labelspace");
			xc.mx_in.ml_index = ls;
		} else if (strcmp(*argv, "ilm_label") == 0) {
			NEXT_ARG();
			mpls_parse_label(&xc.mx_in, &argc, &argv);
		} else if (strcmp(*argv, "nhlfe_key") == 0) {
			__u32 key;
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid key");
			xc.mx_out.u.ml_key = key;
			xc.mx_out.ml_type = MPLS_LABEL_KEY;
		} else {
			usage();
		}
		argc--; argv++;
	}

	if (!xc.mx_in.ml_type) {
		fprintf(stderr, "you must specify a ILM label value\n");
		//exit(1);
		return 1;
	}

	if (!xc.mx_out.u.ml_key) {
		fprintf(stderr, "you must specify a NHLFE key\n");
		//exit(1);
		return 1;
	}

	addattr_l(&req.n, sizeof(req), MPLS_ATTR_XC, &xc, sizeof(xc));

	if (rtnl_talk(&rth2, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		return 2;
		//exit(2);

	return 0;
}

int
mpls_labelspace_modify(int cmd, unsigned flags, int argc, char **argv)
{
	__u32 labelspace = -2;
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr 	n;
		char			buf[4096];
	} req;
	struct mpls_labelspace_req 	ls;

	memset(&req, 0, sizeof(req));
	memset(&ls, 0, sizeof(ls));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = PF_MPLS;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			ls.mls_ifindex = ll_name_to_index(*argv);
		} else if (strcmp(*argv, "labelspace") == 0) {
			NEXT_ARG();
			if (get_unsigned(&labelspace, *argv, 0))
				invarg(*argv, "invalid labelspace");
			ls.mls_labelspace = labelspace;
		} else {
			usage();
		}
		argc--; argv++;
	}

	if (ls.mls_ifindex == 0 || ls.mls_labelspace == -2) {
		fprintf(stderr, "Invalid arguments\n");
		//exit(1);
		return 1;
	}

	addattr_l(&req.n, sizeof(req), MPLS_ATTR_LABELSPACE, &ls, sizeof(ls));

	if (rtnl_talk(&rth2, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		return 2;
		//exit(2);

	return 0;
}

int
mpls_tunnel_modify(int cmd, int argc, char **argv)
{
	unsigned int key = -2;
	struct ifreq ifr;
	int err;
	int fd;

	memset(&ifr, 0, sizeof(ifr));

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			strncpy(ifr.ifr_name, *argv, IFNAMSIZ);
		} else if (strcmp(*argv, "nhlfe") == 0) {
			NEXT_ARG();
			if (get_unsigned(&key, *argv, 0))
				invarg(*argv, "invalid NHLFE key");
			ifr.ifr_ifru.ifru_ivalue = key;
		} else {
			usage();
		}
		argc--; argv++;
	}

	if (!strlen(ifr.ifr_name)) {
		fprintf(stderr, "You must specify a interface name\n");
		//exit(1);
		return 1;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	err = ioctl(fd, cmd, &ifr);
	if (err)
		perror("ioctl");

	return 0;
}

int
mpls_tunnel_add(int cmd, unsigned flags, int argc, char **argv)
{
	//__u32 labelspace = -2;
	struct genlmsghdr		*ghdr;
	struct {
		struct nlmsghdr 	n;
		char			buf[4096];
	} req;
	struct mpls_tunnel_req 	ls;

	memset(&req, 0, sizeof(req));
	memset(&ls, 0, sizeof(ls));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = PF_MPLS;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			//ls.mls_ifindex = ll_name_to_index(*argv);
			strncpy(ls.mt_ifname, *argv, IFNAMSIZ);
		} /*else if (strcmp(*argv, "labelspace") == 0) {
			NEXT_ARG();
			if (get_unsigned(&labelspace, *argv, 0))
				invarg(*argv, "invalid labelspace");
			ls.mls_labelspace = labelspace;
		} */else {
			usage();
		}
		argc--; argv++;
	}
/*
	if (ls.mls_ifindex == 0 || ls.mls_labelspace == -2) {
		fprintf(stderr, "Invalid arguments\n");
		exit(1);
	}*/

	addattr_l(&req.n, sizeof(req), MPLS_ATTR_TUNNEL, &ls, sizeof(ls));

	if (rtnl_talk(&rth2, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		return 2;
		//exit(2);

	return 0;
}

void print_mpls_stats(FILE *fp, struct gnet_stats_basic *st)
{
	fprintf(fp, " (%llu bytes, %u pkts)",
		(unsigned long long)st->bytes, st->packets);
	sprintf(print_mpls_stats_buf," (%llu bytes, %u pkts)",
		(unsigned long long)st->bytes, st->packets);
}

void print_address(FILE *fp, struct sockaddr *addr) {
	char buf[256];
	switch (addr->sa_family) {
		case AF_INET:
		{
			struct sockaddr_in *sin = (struct sockaddr_in*)addr;
			inet_ntop(addr->sa_family, &sin->sin_addr,
				buf, sizeof(buf));
			fprintf(fp, "ipv4 %s ", buf);
			sprintf(print_address_buf,"ipv4 %s ", buf);
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)addr;
			inet_ntop(addr->sa_family, &sin6->sin6_addr,
				buf, sizeof(buf));
			fprintf(fp, "ipv6 %s ", buf);
			sprintf(print_address_buf,"ipv6 %s ", buf);
			break;
		}
		case AF_PACKET:
		{
			fprintf(fp, "packet");
			sprintf(print_address_buf,"packet");
			break;
		}
		default:
			fprintf(fp, "<unknown address family %d> ",
				addr->sa_family);
			sprintf(print_address_buf,"<unknown address family %d> ",
				addr->sa_family);
	}
}

void print_label(FILE *fp, struct mpls_label *label) {
	switch (label->ml_type) {
		case MPLS_LABEL_GEN:
			fprintf(fp, "gen %d ", label->u.ml_gen);
			sprintf(print_label_buf,"gen %d ", label->u.ml_gen);
			break;
		case MPLS_LABEL_ATM:
			fprintf(fp, "atm %d/%d ", label->u.ml_atm.mla_vpi,
				label->u.ml_atm.mla_vci);
			sprintf(print_label_buf,"atm %d/%d ", label->u.ml_atm.mla_vpi,
				label->u.ml_atm.mla_vci);
			break;
		case MPLS_LABEL_FR:
			fprintf(fp, "fr %d ", label->u.ml_fr);
			sprintf(print_label_buf,"fr %d ", label->u.ml_fr);
			break;
		case MPLS_LABEL_KEY:
			fprintf(fp, "key 0x%08x ", label->u.ml_key);
			sprintf(print_label_buf,"key 0x%08x ", label->u.ml_key);
			break;
		default:
			fprintf(fp, "<unknown label type %d> ", label->ml_type);
			sprintf(print_label_buf,"<unknown label type %d> ", label->ml_type);
	}
}

void print_instructions(FILE *fp, struct mpls_instr_req *instr) 
{
	struct mpls_instr_elem *ci;   /* current instruction */
	unsigned int key;
	int i,j;

	for(i = 0;i < instr->mir_instr_length;i++) {
		ci = &instr->mir_instr[i];

		switch (ci->mir_opcode) {
			case MPLS_OP_NOP:
				fprintf(fp, "noop ");
				sprintf(print_instructions_buf, "%snoop ",print_instructions_buf);
				break;
			case MPLS_OP_POP:
				fprintf(fp, "pop ");
				sprintf(print_instructions_buf, "%spop ",print_instructions_buf);
				break;
			case MPLS_OP_PEEK:
				fprintf(fp, "peek ");
				sprintf(print_instructions_buf, "%speek ",print_instructions_buf);
				break;
			case MPLS_OP_PUSH:
				fprintf(fp, "push ");
				print_label(fp, &ci->mir_push);
				sprintf(print_instructions_buf, "%spush ",print_instructions_buf);
				sprintf(print_instructions_buf, "%s%s",print_instructions_buf,print_label_buf);
				break;
			case MPLS_OP_FWD:
				fprintf(fp, "forward ");
				print_label(fp, &ci->mir_fwd);
				sprintf(print_instructions_buf, "%sforward %s "
				,print_instructions_buf,print_label_buf);
				//sprintf(print_instructions_buf, "%s %s",print_instructions_buf,print_label_buf);
				break;
			case MPLS_OP_DLV:
				fprintf(fp, "deliver ");
				sprintf(print_instructions_buf,"%sdeliver ",print_instructions_buf);
				break;
			case MPLS_OP_SET:
				fprintf(fp, "set %s ",
					ll_index_to_name(ci->mir_set.mni_if));
				print_address(fp, &ci->mir_set.mni_addr);
				sprintf(print_instructions_buf,"%sset %s ",
					print_instructions_buf,ll_index_to_name(ci->mir_set.mni_if));
				sprintf(print_instructions_buf,"%s%s",print_instructions_buf,print_address_buf);
				break;				
			case MPLS_OP_SET_RX:
				fprintf(fp, "set-rx-if %s ",
					ll_index_to_name(ci->mir_set_rx));
				sprintf(print_instructions_buf,"%sset-rx-if %s ",
					print_instructions_buf,ll_index_to_name(ci->mir_set_rx));
				break;
			case MPLS_OP_SET_TC:
				fprintf(fp, "set-tcindex %hu ",ci->mir_set_tc);
				sprintf(print_instructions_buf,"%sset-tcindex %hu "
				,print_instructions_buf,ci->mir_set_tc);
				break;
			case MPLS_OP_SET_DS:
				fprintf(fp, "set-dscp %hu ",ci->mir_set_ds);
				sprintf(print_instructions_buf,"%sset-dscp %hu "
				,print_instructions_buf,ci->mir_set_ds);
				break;
			case MPLS_OP_SET_EXP:
				fprintf(fp, "set-exp %hhu ",ci->mir_set_exp);
				sprintf(print_instructions_buf,"%sset-exp %hhu "
				,print_instructions_buf,ci->mir_set_exp);
				break;	
			case MPLS_OP_NF_FWD:
				fprintf(fp, "nffwd 0x%2.2hhx ",
					ci->mir_nf_fwd.nf_mask);
				sprintf(print_instructions_buf,"%snffwd 0x%2.2hhx ",
					print_instructions_buf,ci->mir_nf_fwd.nf_mask);
				for(j=0;j<MPLS_NFMARK_NUM;j++) {
					key = ci->mir_nf_fwd.nf_key[j];
					if (key){
						 fprintf(fp,"%d %8.8x ",j,key);
						 sprintf(print_instructions_buf,"%s%d %8.8x ",print_instructions_buf,j,key);
					}
				}
				break;
			case MPLS_OP_DS_FWD:
				fprintf(fp, "dsfwd 0x%2.2hhx ",
					ci->mir_ds_fwd.df_mask);
				sprintf(print_instructions_buf,"%sdsfwd 0x%2.2hhx ",
					print_instructions_buf,ci->mir_ds_fwd.df_mask);
				for(j=0;j<MPLS_DSMARK_NUM;j++) {
					key = ci->mir_ds_fwd.df_key[j];
					if (key){
						 fprintf(fp,"%d %8.8x ",j,key);
						 sprintf(print_instructions_buf,"%s%d %8.8x ",print_instructions_buf,j,key);
					}
				}
				break;
			case MPLS_OP_EXP_FWD:
				fprintf(fp, "exp-fwd ");
				sprintf(print_instructions_buf,"%sexp-fwd "
				,print_instructions_buf);
				
				for(j=0;j<MPLS_EXP_NUM;j++) {
					key = ci->mir_exp_fwd.ef_key[j];
					if (key){
						 fprintf(fp,"%d %8.8x ",j,key);
						 sprintf(print_instructions_buf,"%s%d %8.8x ",print_instructions_buf,j,key);
					}
				}
				break;
			case MPLS_OP_EXP2TC:
				fprintf(fp, "exp2tc ");
				sprintf(print_instructions_buf,"%sexp2tc ",print_instructions_buf);
				
				for(j=0;j<MPLS_EXP_NUM;j++) {
					fprintf(fp,"%d %hu ",
						j,ci->mir_exp2tc.e2t[j]);
					sprintf(print_instructions_buf,"%s%d %hu ",
						print_instructions_buf,j,ci->mir_exp2tc.e2t[j]);
				}
				break;
			case MPLS_OP_EXP2DS:
				fprintf(fp, "exp2ds ");
				sprintf(print_instructions_buf,"%sexp2ds "
				,print_instructions_buf);

				for(j=0;j<MPLS_EXP_NUM;j++) {
					fprintf(fp,"%d %hhu ",
						j,ci->mir_exp2ds.e2d[j]);
					sprintf(print_instructions_buf,"%s%d %hhu ",
						print_instructions_buf,j,ci->mir_exp2ds.e2d[j]);
				}
				break;
			case MPLS_OP_TC2EXP:
				fprintf(fp, "tc2exp 0x%2.2hhx ",
					ci->mir_tc2exp.t2e_mask);
				sprintf(print_instructions_buf,"%stc2exp 0x%2.2hhx ",
					print_instructions_buf,ci->mir_tc2exp.t2e_mask);

				for(j=0;j<MPLS_TCINDEX_NUM;j++) {
					fprintf(fp,"%d %hhu ",
						j,ci->mir_tc2exp.t2e[j]);
					sprintf(print_instructions_buf,"%s%d %hhu ",
						print_instructions_buf,j,ci->mir_tc2exp.t2e[j]);
				}
				break;
			case MPLS_OP_DS2EXP:
				fprintf(fp, "ds2exp 0x%2.2hhx ",
					ci->mir_ds2exp.d2e_mask);
				sprintf(print_instructions_buf,"%sds2exp 0x%2.2hhx ",
					print_instructions_buf,ci->mir_ds2exp.d2e_mask);

				for(j=0;j<MPLS_DSMARK_NUM;j++) {
					fprintf(fp,"%d %hhu ",
						j,ci->mir_ds2exp.d2e[j]);
					sprintf(print_instructions_buf,"%s%d %hhu ",
						print_instructions_buf,j,ci->mir_ds2exp.d2e[j]);
				}
				break;
			case MPLS_OP_NF2EXP:
				fprintf(fp, "nf2exp 0x%2.2hhx ",
					ci->mir_nf2exp.n2e_mask);
				sprintf(print_instructions_buf,"%snf2exp 0x%2.2hhx ",
					print_instructions_buf,ci->mir_nf2exp.n2e_mask);

				for(j=0;j<MPLS_NFMARK_NUM;j++) {
					fprintf(fp,"%d %hhu ",
						j,ci->mir_nf2exp.n2e[j]);
					sprintf(print_instructions_buf,"%s%d %hhu ",
						print_instructions_buf,j,ci->mir_nf2exp.n2e[j]);
				}
				break;	
			default:
				fprintf(fp, "<unknown opcode %d> ", 
					ci->mir_opcode);
				sprintf(print_instructions_buf,"%s<unknown opcode %d> ", 
					print_instructions_buf,ci->mir_opcode);
		}
	}
}

int print_ilm(const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_in_label_req *mil;
	struct mpls_instr_req *instr;
	struct gnet_stats_basic *stats;
        struct genlmsghdr *ghdr = NLMSG_DATA(n);

	if ((ghdr->cmd != MPLS_CMD_NEWILM &&
	    ghdr->cmd != MPLS_CMD_DELILM) ||
	    (!tb[MPLS_ATTR_ILM])) {
		fprintf(stderr, "Not an ILM\n");
		sprintf(mpls_table,"%s","Not an ILM\r\n");//add by here
		return -1;
	}

	if (ghdr->cmd == MPLS_CMD_DELILM){
		fprintf(fp, "deleted ILM entry ");
		sprintf(mpls_table,"%s%s",mpls_table,"deleted ILM entry ");//add by here
	}
	
	if (ghdr->cmd == MPLS_CMD_NEWILM){
		fprintf(fp, "ILM entry ");
		sprintf(mpls_table,"%s%s",mpls_table,"ILM entry ");//add by here
	}
	
	mil = RTA_DATA(tb[MPLS_ATTR_ILM]);
	instr = RTA_DATA(tb[MPLS_ATTR_INSTR]);
	stats = RTA_DATA(tb[MPLS_ATTR_STATS]);

	fprintf(fp, "label ");
	print_label(fp, &mil->mil_label);

	fprintf(fp, "labelspace %d ", mil->mil_label.ml_index);
	/* add by here to get ilm table to vty_out*/
	sprintf(mpls_table,"%s%s%s labelspace %d ",mpls_table,
	"label ",print_label_buf,mil->mil_label.ml_index);//add by here
	/*end by here */

	switch(mil->mil_proto) {
		case AF_INET:
			fprintf(fp, "proto ipv4 ");
			sprintf(mpls_table,"%s%s",mpls_table,"proto ipv4 ");
			break;
		case AF_INET6:
			fprintf(fp, "proto ipv6 ");
			sprintf(mpls_table,"%s%s",mpls_table,"proto ipv6 ");
			break;
		case AF_PACKET:
			fprintf(fp, "proto packet ");
			sprintf(mpls_table,"%s%s",mpls_table,"proto packet ");
			break;
		default:
			fprintf(fp, "<unknown proto %d> ", mil->mil_proto);
			sprintf(mpls_table,"%s <unknown proto %d> ",mpls_table, mil->mil_proto);
	}

	fprintf(fp, "\n\t");
	sprintf(mpls_table,"%s\r\n\t",mpls_table);
	if (instr && instr->mir_instr_length) {
		print_instructions(fp, instr);
		sprintf(mpls_table,"%s%s",mpls_table,print_instructions_buf);
		flush_print_instructions_buf();
	}

	if (stats)
		print_mpls_stats(fp, stats);

	fprintf(fp, "\n");
	fflush(fp);
	sprintf(mpls_table,"%s%s \r\n",mpls_table,print_mpls_stats_buf);
	
	return 0;
}

int print_xc(const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_xconnect_req *xc;
        struct genlmsghdr *ghdr = NLMSG_DATA(n);

	if ((ghdr->cmd != MPLS_CMD_NEWXC &&
	    ghdr->cmd != MPLS_CMD_DELXC) ||
	    (!tb[MPLS_ATTR_XC])) {
		fprintf(stderr, "Not an XC\n");
		sprintf(mpls_table,"%s","Not an XC\r\n"); //ad by here
		return -1;
	}

	xc = RTA_DATA(tb[MPLS_ATTR_XC]);

	if (ghdr->cmd == MPLS_CMD_DELXC)
		fprintf(fp, "deleted XC entry ");

	if (ghdr->cmd == MPLS_CMD_NEWXC)
		fprintf(fp, "XC entry ");
  
	fprintf(fp, "ilm_label ");
	print_label(fp, &xc->mx_in);
	fprintf(fp, "ilm_labelspace %d ", xc->mx_in.ml_index);
	fprintf(fp, "nhlfe_key 0x%08x ",xc->mx_out.u.ml_key);
	fprintf(fp, "\n");
	fflush(fp);
	 /* add by here to get labelspace information to vty_out*/
	
	sprintf(mpls_table,"%s%s",mpls_table,"ilm_label ");
  sprintf(mpls_table,"%s%s",mpls_table,print_label_buf);
  sprintf(mpls_table,"%s ilm_labelspace %d nhlfe_key 0x%08x \r\n",mpls_table,xc->mx_in.ml_index, 
  xc->mx_out.u.ml_key);
	 /* end by here*/
	return 0;
}

int print_labelspace(const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_labelspace_req *ls;
        struct genlmsghdr *ghdr = NLMSG_DATA(n);

	if ((ghdr->cmd != MPLS_CMD_SETLABELSPACE) ||
	    (!tb[MPLS_ATTR_LABELSPACE])) {
		fprintf(stderr, "Not an Labelspace\n");
		sprintf(mpls_table,"%s","LABELSPACE entry \r\n"); //ad by here
		return -1;
	}

	ls = RTA_DATA(tb[MPLS_ATTR_LABELSPACE]);

	fprintf(fp, "LABELSPACE entry ");

	fprintf(fp, "dev %s ", ll_index_to_name(ls->mls_ifindex));
	fprintf(fp, "labelspace %d ",ls->mls_labelspace);
	fprintf(fp, "\n");
	fflush(fp);
  /* add by here to get labelspace information to vty_out*/
  sprintf(mpls_table,"%s%s dev %s labelspace %d \r\n",mpls_table,"LABELSPACE entry", 
  ll_index_to_name(ls->mls_ifindex),ls->mls_labelspace);
  /* end by here*/
  
	return 0;
}

int print_nhlfe(const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_out_label_req *mol;
	struct mpls_instr_req *instr;
	struct gnet_stats_basic *stats;
        struct genlmsghdr *ghdr = NLMSG_DATA(n);

	if ((ghdr->cmd != MPLS_CMD_NEWNHLFE &&
	    ghdr->cmd != MPLS_CMD_DELNHLFE) ||
	    (!tb[MPLS_ATTR_NHLFE])) {
		fprintf(stderr, "Not a NHLFE\n");
		sprintf(mpls_table,"%s","Not a NHLFE \r\n"); //ad by here
		return -1;
	}

	mol = RTA_DATA(tb[MPLS_ATTR_NHLFE]);
	instr = RTA_DATA(tb[MPLS_ATTR_INSTR]);
	stats = RTA_DATA(tb[MPLS_ATTR_STATS]);

	if (ghdr->cmd == MPLS_CMD_DELNHLFE){
		fprintf(fp, "deleted NHLFE entry ");
		sprintf(mpls_table,"%s%s",mpls_table,"deleted NHLFE entry "); //ad by here
	}
	if (ghdr->cmd == MPLS_CMD_NEWNHLFE){
		fprintf(fp, "NHLFE entry ");
		sprintf(mpls_table,"%s%s",mpls_table,"NHLFE entry "); //ad by here
	}
	fprintf(fp, "key 0x%08x ", mol->mol_label.u.ml_key);
	fprintf(fp, "mtu %d ",mol->mol_mtu);
	
	add_olabel_key=mol->mol_label.u.ml_key; //add by here
	sprintf(mpls_table,"%s key 0x%08x mtu %d ",mpls_table,
	 mol->mol_label.u.ml_key,mol->mol_mtu); //ad by here

	
	if (mol->mol_propagate_ttl) {
		fprintf(fp, "propagate_ttl ");
		sprintf(mpls_table,"%s%s",mpls_table,"propagate_ttl "); //ad by here
	}
	fprintf(fp, "\n\t");
	sprintf(mpls_table,"%s\r\n\t",mpls_table); //ad by here
	if (instr && instr->mir_instr_length) {
		print_instructions(fp, instr);
		sprintf(mpls_table,"%s%s",mpls_table,print_instructions_buf); //ad by here
		flush_print_instructions_buf();
	}

	if (stats){
		print_mpls_stats(fp, stats);
		sprintf(mpls_table,"%s%s",mpls_table,print_mpls_stats_buf); //ad by here
	}
	fprintf(fp, "\n");
  sprintf(mpls_table,"%s\r\n",mpls_table); //ad by here
	fflush(fp);
	return 0;
}

#if 0
int print_tunnel(const struct nlmsghdr *n, void *arg, struct rtattr **tb)
{
	FILE *fp = (FILE*)arg;
	struct mpls_tunnel_req *t = NLMSG_DATA(n);
	int len = n->nlmsg_len;

	if (n->nlmsg_type != MPLS_RTM_ADDTUNNEL &&
		n->nlmsg_type != MPLS_RTM_DELTUNNEL) {
		fprintf(stderr, "Not a TUNNEL\n");
		return 0;
	}

	if (n->nlmsg_type == MPLS_RTM_DELTUNNEL)
		fprintf(fp, "deleted TUNNEL entry ");

	if (n->nlmsg_type == MPLS_RTM_ADDTUNNEL)
		fprintf(fp, "TUNNEL entry ");

	fprintf(fp, "%s 0x%08x", t->mt_ifname, t->mt_nhlfe_key);
	fprintf(fp, "\n");

	fflush(fp);
	return 0;
}
#endif

int print_mpls(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct rtattr *tb[MPLS_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *attrs;

	if (n->nlmsg_type !=  PF_MPLS) {
		fprintf(stderr, "Not a controller message, nlmsg_len=%d "
			"nlmsg_type=0x%x\n", n->nlmsg_len, n->nlmsg_type);
		return 0;
	}

        len -= NLMSG_LENGTH(GENL_HDRLEN);
        if (len < 0) {
                fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
                return -1;
        }

	attrs = (struct rtattr *) ((char *) ghdr + GENL_HDRLEN);
	parse_rtattr(tb, MPLS_ATTR_MAX, attrs, len);

	switch (ghdr->cmd) {
		case MPLS_CMD_NEWILM:
			return print_ilm(n,arg,tb);
		case MPLS_CMD_NEWNHLFE:
			return print_nhlfe(n,arg,tb);
		case MPLS_CMD_NEWXC:
			return print_xc(n,arg,tb);
		case MPLS_CMD_SETLABELSPACE:
			return print_labelspace(n,arg,tb);
		default:
			return 0;
	}

#if 0
	if (n->nlmsg_type >= MPLS_RTM_ADDTUNNEL &&
		n->nlmsg_type <= MPLS_RTM_DELTUNNEL) {
		return print_tunnel(n,arg, tb);
	}
#endif
	return 0;
}

int mpls_list(int cmd,int argc, char **argv)
{
	struct genlmsghdr *ghdr;
	struct rtnl_handle rth;

	struct {
		struct nlmsghdr		n;
		char			buf[4096];
	} req;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC) < 0) {
		fprintf (stderr, "Error opening nl socket\n");
		//exit(-1);
		return -1;
	}
	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.n.nlmsg_type = PF_MPLS;
	req.n.nlmsg_seq = rth.dump = ++rth.seq;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = cmd;
	
	if (rtnl_send(&rth, (const char *)&req.n, req.n.nlmsg_len) < 0) {
		perror("Cannot send dump request");
		//exit(1);
		return 1;
	}

	if (rtnl_dump_filter(&rth, print_mpls, stdout, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		//exit(1);
		return 1;
	}
	rtnl_close(&rth);

	return 0;
}

int do_ilm(int argc, char **argv) {

	if (argc <= 0 || matches(*argv, "list") == 0 ||
		matches(*argv, "show") == 0)
		return mpls_list(MPLS_CMD_GETILM,argc-1, argv+1);
	if (matches(*argv, "add") == 0)
		return mpls_ilm_modify(MPLS_CMD_NEWILM, NLM_F_CREATE,
			argc-1, argv+1);
	if (matches(*argv, "change") == 0)
		return mpls_ilm_modify(MPLS_CMD_NEWILM, 0, argc-1, argv+1);
	if (matches(*argv, "delete") == 0)
		return mpls_ilm_modify(MPLS_CMD_DELILM, 0, argc-1, argv+1);
	if (matches(*argv, "help") == 0)
		usage();
	else {
		fprintf(stderr,
		    "Option \"%s\" is unknown, try \"mpls -help\".\n", argv[0]);
		return -EINVAL;
	}

	return 0;
}

int do_nhlfe(int argc, char **argv)
{
	if (argc <= 0 || matches(*argv, "list") == 0 ||
	    matches(*argv, "show") == 0)
		return mpls_list(MPLS_CMD_GETNHLFE,argc-1, argv+1);
	if (matches(*argv, "add") == 0)
		return mpls_nhlfe_modify(MPLS_CMD_NEWNHLFE,
		    NLM_F_CREATE, argc-1, argv+1);
	if (matches(*argv, "change") == 0)
		return mpls_nhlfe_modify(MPLS_CMD_NEWNHLFE, 0, argc-1, argv+1);
	if (matches(*argv, "delete") == 0)
		return mpls_nhlfe_modify(MPLS_CMD_DELNHLFE, 0, argc-1, argv+1);
	if (matches(*argv, "help") == 0)
		usage();
	else {
		fprintf(stderr,
		    "Option \"%s\" is unknown, try \"mpls -help\".\n", argv[0]);
		return -EINVAL;
	}

	return 0;
}

int do_xc(int argc, char **argv) {

	if (argc <= 0 || matches(*argv, "list") == 0 ||
	    matches(*argv, "show") == 0)
		return mpls_list(MPLS_CMD_GETXC,argc-1, argv+1);
	if (matches(*argv, "add") == 0)
		return mpls_xc_modify(MPLS_CMD_NEWXC, NLM_F_CREATE,
			argc-1, argv+1);
	if (matches(*argv, "delete") == 0)
		return mpls_xc_modify(MPLS_CMD_DELXC, 0, argc-1, argv+1);
	if (matches(*argv, "help") == 0)
		usage();
	else {
		fprintf(stderr,
		    "Option \"%s\" is unknown, try \"mpls -help\".\n", argv[0]);
		return -EINVAL;
	}

	return 0;
}

int do_labelspace(int argc, char **argv) {

	if (argc <= 0 || matches(*argv, "list") == 0 ||
	    matches(*argv, "show") == 0)
		return mpls_list(MPLS_CMD_GETLABELSPACE,argc-1, argv+1);
	if (matches(*argv, "set") == 0)
		return mpls_labelspace_modify(MPLS_CMD_SETLABELSPACE,
			0, argc-1, argv+1);
	if (matches(*argv, "help") == 0)
		usage();
	else {
		fprintf(stderr,
		    "Option \"%s\" is unknown, try \"mpls -help\".\n", argv[0]);
		return -EINVAL;
	}

	return 0;
}

int do_tunnel(int argc, char **argv) {
#if 0
	if (argc <= 0 || matches(*argv, "list") == 0 ||
	    matches(*argv, "show") == 0)
		return mpls_list(SHIM_VIRT,argc-1, argv+1);
#endif
	if (matches(*argv, "set") == 0)
		return mpls_tunnel_modify(SIOCDEVPRIVATE, argc-1, argv+1);
	if (matches(*argv, "get") == 0)
		return mpls_tunnel_modify(SIOCDEVPRIVATE + 1, argc-1, argv+1);
	if (matches(*argv, "add") == 0)
		return mpls_tunnel_add(MPLS_CMD_ADDTUNNEL,0, argc-1, argv+1);
	if (matches(*argv, "delete") == 0)
		return mpls_tunnel_add(MPLS_CMD_DELTUNNEL,0, argc-1, argv+1);
	if (matches(*argv, "help") == 0)
		usage();
	else {
		fprintf(stderr,
		    "Option \"%s\" is unknown, try \"mpls -help\".\n", argv[0]);
		return -EINVAL;
	}

	return 0;
}

char *get_mpls_table(){
	
	return mpls_table;
}

/*char print_instructions_buf[50]={0};
char print_address_buf[50]={0};
char print_mpls_stats_buf[50]={0};*/
void flush_print_label_buf(){
	sprintf(print_label_buf,"%s","");
}
void flush_print_instructions_buf(){
	sprintf(print_instructions_buf,"%s","");
}
void flush_print_address_buf(){
	sprintf(print_address_buf,"%s","");
}
void flush_print_mpls_stats_buf(){
	sprintf(print_mpls_stats_buf,"%s","");
}

void flush_mpls_table(){
	sprintf(mpls_table,"%s","");
}

void flush_mpls_buffer(){
	flush_mpls_table();
	flush_print_label_buf();
	flush_print_instructions_buf();
	flush_print_address_buf();
	flush_print_mpls_stats_buf();
}
//int main(int argc, char **argv) {
int mpls_action(int argc, char **argv) {
	char *basename;
	int retval;

	basename = strrchr(argv[0], '/');
	if (basename == NULL)
		basename = argv[0];
	else
		basename++;

	while (argc > 1) {
		if (argv[1][0] != '-')
			break;
		if (matches(argv[1], "-Version") == 0) {
			printf("mpls utility, iproute2-ss%s mpls-linux %d.%d%d%d\n",
				SNAPSHOT, (MPLS_LINUX_VERSION >> 24) & 0xFF,
				(MPLS_LINUX_VERSION >> 16) & 0xFF,
				(MPLS_LINUX_VERSION >> 8) & 0xFF,
				(MPLS_LINUX_VERSION) & 0xFF);
			//exit(0);
			return 0;
		} else if (matches(argv[1], "-help") == 0) {
			usage();
		} else {
			fprintf(stderr, "Option \"%s\" is unknown, try \"mpls -help\".\n", argv[1]);
			//exit(-1);
			return -1 ;
		}
		argc--;	argv++;
	}

	if (argc > 1) {
		if (rtnl_open(&rth1, 0) < 0) {
			fprintf (stderr, "Error openning netlink socket\n");
			//exit(-1);
			return -1;
		}
		ll_init_map(&rth1);
		rtnl_close(&rth1);

		if (matches(argv[1], "monitor") == 0) {
			retval = do_mplsmonitor(argc-2,argv+2);
		} else {
			if (rtnl_open_byproto(&rth1, MPLS_GRP_NHLFE,
				NETLINK_GENERIC) < 0) {
				fprintf (stderr,"Error opening NHLFE rtnl\n");
				//exit(-1);
				return -1;
			}
			if (rtnl_open_byproto(&rth2, 0, NETLINK_GENERIC) < 0) {
				fprintf (stderr,"Error opening generic rtnl\n");
				//exit(-1);
				return -1;
			}
			if (matches(argv[1], "nhlfe") == 0) {
				retval = do_nhlfe(argc-2,argv+2);
			} else if (matches(argv[1], "ilm") == 0) {
				retval = do_ilm(argc-2,argv+2);
			} else if (matches(argv[1], "xc") == 0) {
				retval = do_xc(argc-2,argv+2);
			} else if (matches(argv[1], "labelspace") == 0) {
				retval = do_labelspace(argc-2,argv+2);
			} else if (matches(argv[1], "tunnel") == 0) {
				retval = do_tunnel(argc-2,argv+2);
			} else {
				usage();
				retval = 1;
			}
			rtnl_close(&rth1);
			rtnl_close(&rth2);
		}
	} else {
		usage();
		retval = 1;
	}
	if(add_olabel_key) //add by here
		retval=add_olabel_key; //add by here return mpls out label key.
	printf("MPLS OUT label key:%d\n",retval);
	return retval;
}
