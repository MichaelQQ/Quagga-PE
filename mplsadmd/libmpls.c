/* written by pim.vanheuven@intec.rug.ac.be
   basically interfacing with (slightly modified mplsadm)

   This program is free software; you can redistribute it and/or 
   modify it under the terms of the GNU General Public License   
   as published by the Free Software Foundation; either version  
   2 of the License, or (at your option) any later version.      
*/

//GIOVANNA for DIFFSERV
#ifndef _rsvp_diffserv_h_
#include "rsvp_diffserv.h"
#endif
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>  //PT for strlen

#include "libmpls.h"
#include "mpls.h"
#include "ds_mpls.h"

/* PVH interface with mplsadm. 
   in mpls.c:
     change main() to mpls_action()
     set optind=1 before call to getopt()
*/
#define MAXARGS 30
int arg_index = 0;
char** args;
char buffer[1024]={0};

void alloc_args(void){
  arg_index = 1;
  args = (char**) malloc (MAXARGS*sizeof(char*));
  args[0] = (char*) malloc(sizeof("mps"));
  sprintf(args[0], "mpls");  
}

void free_args(void){
  int i;
  for (i=0; i<arg_index; ++i)
    free(args[i]);
  free(args);
}

void set_arg(const char* argument){
  args[arg_index] = (char*) malloc(sizeof(char)*(strlen(argument)+1));
  sprintf(args[arg_index++], "%s", argument);
}

int add_label_space(const char* interface, int label_space_no){
 /* int res;
  alloc_args();
  set_arg("-L");
  sprintf(buffer, "%s:%d", interface, label_space_no);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):add_label_space enter.\n");
  //./mpls labelspace set dev eth2 labelspace 0
  //add_label_space interface WORD label_space_no <0-65535>
  int res;
  alloc_args();
  set_arg("labelspace");
  set_arg("set");
  set_arg("dev");
  sprintf(buffer, "%s", interface);
  set_arg(buffer);
  set_arg("labelspace");
  sprintf(buffer, "%d", label_space_no);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):add_label_space exit. res:%d.\n",res);
  return res;
}

int del_label_space(const char* interface){
 /* int res;
  alloc_args();
  set_arg("-L");
  sprintf(buffer, "%s:%d", interface, -1);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):del_label_space enter.\n");
  //./mpls labelspace set dev eth2 labelspace -1
  int res;
  alloc_args();
  set_arg("labelspace");
  set_arg("set");
  set_arg("dev");
  sprintf(buffer, "%s", interface);
  set_arg(buffer);
  set_arg("labelspace");
  sprintf(buffer, "%d", -1);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):del_label_space exit. res:%d.\n",res);
  return res;
}

//not used on rsvpd 
int add_fec_to_label(int table, const char* fec, int label, int exp, 
		     const char* iface, const char* nh,struct vty *vty){
 /* int res;
  alloc_args();
  assert(exp<8);
  set_arg("-ABO");
  sprintf(buffer, "gen:%d:%s:ipv4:%s", label,  iface, nh);
  set_arg("-f");
  sprintf(buffer, "%s",fec);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
}


int add_olabel(int label, const char* iface, const char* nh){
/* int res;
 alloc_args();
 set_arg("-AO 0");
 res = mpls_action(arg_index, args);
 free_args();
 alloc_args();
 set_arg("-O");
 sprintf(buffer, "%d", res); // :%d:%s", res, label, iface);
 set_arg(buffer);
 set_arg("-o");
//sprintf(buffer, "ds2exp:%s:exp2tc:%s:push:gen:%d:set:%s:ipv4:%s", DS2EXPMAP, 
//	 EXP2TCMAP, label, iface, nh);
 sprintf(buffer, "push:gen:%d:set:%s:ipv4:%s", label, iface, nh);
 set_arg(buffer);
 mpls_action(arg_index, args);
 free_args();
 // printf("out label key %08x\n", res);
 return res;*/ // this should the key!
  printf("DEBUG(MPLSD):add_olabel enter.\n");
 //./mpls nhlfe add key 0 instructions push gen 200 nexthop eth2 ipv4 172.16.0.2
 	int res;
  alloc_args();
  set_arg("nhlfe");
  set_arg("add");
  set_arg("key");
  sprintf(buffer, "%d", 0);
  set_arg(buffer);
  set_arg("instructions");
  set_arg("push");
  set_arg("gen");
  sprintf(buffer, "%d", label);
  set_arg(buffer);
  set_arg("nexthop");
  sprintf(buffer, "%s", iface);
  set_arg(buffer);
  set_arg("ipv4");
  sprintf(buffer, "%s",	nh);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):add_olabel exit. res:%d.\n",res);
  return res;
}
//used on rsvpd/labeltest/tunnel.c
int add_olabel_exp(int label, int exp, const char* iface, const char* nh){
/*  int res;
 alloc_args();
 set_arg("-AO 0");
 res = mpls_action(arg_index, args);
 free_args();
 alloc_args();
 set_arg("-O");
 sprintf(buffer, "%d", res); // :%d:%s", res, label, iface);
 set_arg(buffer);
 set_arg("-o");
 sprintf(buffer, "set_exp:%d:exp2tc:%s:push:gen:%d:set:%s:ipv4:%s", exp, 
	 EXP2TCMAP, label, iface, 
	 nh);
 set_arg(buffer);
 mpls_action(arg_index, args);
 free_args();
 return res;*/
  printf("DEBUG(MPLSD):add_olabel_exp enter.\n");
 //./mpls nhlfe add key 0 instructions set-exp 2 push gen 10 nexthop eth1 ipv4 192.168.10.95
  int res=-1;
  alloc_args();
  set_arg("nhlfe");
  set_arg("add");
  set_arg("key");
  sprintf(buffer, "%d", 0);
  set_arg(buffer);
  set_arg("instructions");
  set_arg("set-exp");
  sprintf(buffer, "%d", exp);
  set_arg(buffer);
  set_arg("push");
  set_arg("gen");
  sprintf(buffer, "%d", label);
  set_arg(buffer);
  set_arg("nexthop");
  sprintf(buffer, "%s", iface);
  set_arg(buffer);
  set_arg("ipv4");
  sprintf(buffer, "%s",	nh);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):add_olabel_exp exit. res:%d.\n",res);
  return res;
} 

int add_olabel_tc(int label, int tc, const char* iface, const char* nh){
 /* int res;
 alloc_args();
 set_arg("-AO 0");
 res = mpls_action(arg_index, args);
 free_args();
 alloc_args();
 set_arg("-O");
 sprintf(buffer, "%d", res); // :%d:%s", res, label, iface);
 set_arg(buffer);
 set_arg("-o");
 sprintf(buffer, "set_tc:%d:push:gen:%d:set:%s:ipv4:%s", tc, label, iface, nh);
 set_arg(buffer);
 mpls_action(arg_index, args);
 free_args();
 return res;*/
	printf("DEBUG(MPLSD):add_olabel_tc enter.\n");
 //./mpls nhlfe add key 0 instructions set-tcindex 10 push gen 10 nexthop eth1 ipv4 192.168.10.95
  int res=-1;
  alloc_args();
  set_arg("nhlfe");
  set_arg("add");
  set_arg("key");
  sprintf(buffer, "%d", 0);
  set_arg(buffer);
  set_arg("instructions");
  set_arg("set-tcindex");
  sprintf(buffer, "%d", tc);
  set_arg(buffer);
  set_arg("push");
  set_arg("gen");
  sprintf(buffer, "%d", label);
  set_arg(buffer);
  set_arg("nexthop");
  sprintf(buffer, "%s", iface);
  set_arg(buffer);
  set_arg("ipv4");
  sprintf(buffer, "%s",	nh);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):add_olabel_tc exit. res:%d.\n",res);
  return res;
} 
//not used on rsvpd 
int add_olabel_tcindex(int label, const char* iface, const char* nh){
 /* int res;
 alloc_args();
 set_arg("-AO 0");
 res = mpls_action(arg_index, args);
 free_args();
 alloc_args();
 set_arg("-O");
 sprintf(buffer, "%d", res); // :%d:%s", res, label, iface);
 set_arg(buffer);
 set_arg("-o");
 sprintf(buffer, "tc2exp:%s:push:gen:%d:set:%s:ipv4:%s", 
	 TC2EXPMAP, label, iface, 
	 nh);
 set_arg(buffer);
  mpls_action(arg_index, args);
 free_args();
 return res;*/
   int res=-1;
  
  return res;
} 


int del_olabel(int key){ 
/* int res;
  alloc_args();
  set_arg("-DO");
  sprintf(buffer, "%d", key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):del_olabel enter.\n");
  //./mpls nhlfe del key 0x03
  int res;
  alloc_args();
  set_arg("nhlfe");
  set_arg("del");
  set_arg("key");
  sprintf(buffer, "%d", key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):del_olabel exit. res:%d.\n",res);
  return res;
}

int bind_olabel(int label, int key,int labelspace){ 
/* int res;
  alloc_args();
  set_arg("-BI");
  sprintf(buffer, "gen:%d:0", label);
  set_arg(buffer);
  set_arg("-O");
  sprintf(buffer, "%d", key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):bind_olabel enter.\n");
  //./mpls xc add ilm_label gen 1000 ilm_labelspace 0 nhlfe_key 0x2
 	int res;
  alloc_args();
  set_arg("xc");
  set_arg("add");
  set_arg("ilm_label");
  set_arg("gen");
  sprintf(buffer, "%d", label);
  set_arg(buffer);
  set_arg("ilm_labelspace");
  sprintf(buffer, "%d", labelspace);
  set_arg(buffer);
  set_arg("nhlfe_key");
  sprintf(buffer, "%d", key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):bind_olabel exit. res:%d.\n",res);
  return res;
}

//not used on rsvpd 
int del_ilabel(int label, int exp,int labelspace){
 /*int res;
  alloc_args();
  assert(exp<8);
  set_arg("-DI");
  sprintf(buffer, "gen:%d:0", label);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):del_ilabel enter.\n");
  //./mpls ilm delete label gen 10000 labelspace 0
  int res;
  alloc_args();
  set_arg("ilm");
  set_arg("delete");
  set_arg("label");
  set_arg("gen");
  sprintf(buffer, "%d", label);
  set_arg(buffer);
  set_arg("labelspace");
  sprintf(buffer, "%d", labelspace);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  printf("DEBUG(MPLSD):del_ilabel exit. res:%d.\n",res);
  free_args();
  return res;
}
//not used on rsvpd 
int del_fec_to_label(int table, const char* fec, int label, int exp, 
		     const char* iface){
 /* int res;
  alloc_args();
  assert(exp<8);
  set_arg("-DUO");
  sprintf(buffer, "gen:%d:%s:", label, iface);
  set_arg(buffer);
  set_arg("-f");
  sprintf(buffer, "%s",fec);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
}
//not used on rsvpd 
int unbind_fec_to_label(int table, const char* fec, int label, int exp, 
			const char* iface){
 /* int res;
  alloc_args();
  assert(exp<8);
  set_arg("-UO");
  sprintf(buffer, "gen:%d:%s:", label, iface);
  set_arg(buffer);
  set_arg("-f");
  sprintf(buffer, "%s",fec);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
}

int add_label_to_label(int il, int ol, const char* iface, 
		       const char* nh){
/*  int res;
  alloc_args();
  set_arg("-AO 0");
  res = mpls_action(arg_index, args);
  free_args();

  alloc_args();
  set_arg("-O");
  sprintf(buffer, "%d", res); // :%d:%s", res, label, iface);
  set_arg(buffer);
  set_arg("-o");
  sprintf(buffer, "exp2tc:%s:push:gen:%d:set:%s:ipv4:%s", EXP2TCMAP, ol, iface, nh);
  set_arg(buffer);  
  mpls_action(arg_index, args);
  free_args();

 if (il){
   alloc_args();
   set_arg("-AI");
   sprintf(buffer, "gen:%d:0", il);
   set_arg(buffer);
   mpls_action(arg_index, args);
   free_args();

   alloc_args();
   set_arg("-BI");
   sprintf(buffer, "gen:%d:0", il);
   set_arg(buffer);
   set_arg("-O");
   sprintf(buffer, "%d", res);
   set_arg(buffer);
   mpls_action(arg_index, args);
   free_args();
 }
 return res; */// return key of olabel here
 printf("DEBUG(MPLSD):add_label_to_label enter.\n");
  //./mpls nhlfe add key 0 instructions exp2tc 1 0xb8 2 0x28 3 0x30 4 0x48 5 0x50 6 0x68 7 0x70 push gen 10 nexthop eth1 ipv4 192.168.10.95
  int res=-1,i=0;
  char exp2tc_buf[100]={0};
  char *delim=":";
  char *p;  
  
  alloc_args();
  set_arg("nhlfe");
  set_arg("add");
  set_arg("key");
  sprintf(buffer, "%d", 0);
  set_arg(buffer);
  set_arg("instructions");
  set_arg("exp2tc");
  
	sprintf(exp2tc_buf,"%s",EXP2TCMAP);
	sprintf(buffer,"%s",strtok(exp2tc_buf,delim));
	set_arg(buffer);
	while(p=strtok(NULL,delim)){
  	sprintf(buffer,"%s",p);
		set_arg(buffer);
  }
  
  set_arg("push");
  set_arg("gen");
  sprintf(buffer, "%d", ol);
  set_arg(buffer);
  set_arg("nexthop");
  sprintf(buffer, "%s", iface);
  set_arg(buffer);
  set_arg("ipv4");
  sprintf(buffer, "%s",	nh);
  set_arg(buffer);
  /*
  for(i=0; i< arg_index;i++)
  	printf("%s ",args[i]);*/
  res = mpls_action(arg_index, args);
  free_args();
  
  if (il){
   //./mpls ilm add label gen 34 labelspace 0
   alloc_args();
   set_arg("ilm");
   set_arg("add");
   set_arg("label");
   set_arg("gen");
   sprintf(buffer, "%d", il);
   set_arg(buffer);
   set_arg("labelspace");
   sprintf(buffer, "%d", 0);  //default the labelspace value =0
   set_arg(buffer);
   set_arg("proto");// Testing for VPLS packet ...This need to be marked.
   set_arg("packet");//Testing for VPLS packet ...This need to be marked.
   mpls_action(arg_index, args);
   free_args();
   
   //./mpls xc add ilm_label gen 200 ilm_labelspace 0 nhlfe_key 0x3
   alloc_args();
   set_arg("xc");
   set_arg("add");
   set_arg("ilm_label");
   set_arg("gen");
   sprintf(buffer, "%d", il);
   set_arg(buffer);
   set_arg("ilm_labelspace");
   sprintf(buffer, "%d", 0);  //default the labelspace value =0
   set_arg(buffer);
   set_arg("nhlfe_key");
   sprintf(buffer, "%d", res); 
   set_arg(buffer);
   mpls_action(arg_index, args);
   free_args();
	}
	printf("DEBUG(MPLSD):add_label_to_label exit. res:%d.\n",res);
  return res;
}

int add_label_to_label_tc(int il, int ol, int tc, const char* iface, 
			  const char* nh){
 /* int res;
  alloc_args();
  set_arg("-AO 0");
  res = mpls_action(arg_index, args);
  free_args();

  alloc_args();
  set_arg("-O");
  sprintf(buffer, "%d", res); // :%d:%s", res, label, iface);
  set_arg(buffer);
  set_arg("-o");
  sprintf(buffer, "set_tc:%d:push:gen:%d:set:%s:ipv4:%s", tc, ol, iface, nh);
  set_arg(buffer);  
  mpls_action(arg_index, args);
  free_args();

  if (il){
   alloc_args();
   set_arg("-AI");
   sprintf(buffer, "gen:%d:0", il);
   set_arg(buffer);
   mpls_action(arg_index, args);
   free_args();

   alloc_args();
   set_arg("-BI");
   sprintf(buffer, "gen:%d:0", il);
   set_arg(buffer);
   set_arg("-O");
   sprintf(buffer, "%d", res);
   set_arg(buffer);
   mpls_action(arg_index, args);
   free_args();
  }
  return res; */// return key of olabel here
  printf("DEBUG(MPLSD):add_label_to_label_tc enter.\n");
  //./mpls nhlfe add key 0 instructions set-tcindex 10 push gen 10 nexthop eth1 ipv4 192.168.10.95
  int res=-1;
  alloc_args();
  set_arg("nhlfe");
  set_arg("add");
  set_arg("key");
  sprintf(buffer, "%d", 0);
  set_arg(buffer);
  set_arg("instructions");
  set_arg("set-tcindex");
  sprintf(buffer, "%d", tc);
  set_arg(buffer);
  set_arg("push");
  set_arg("gen");
  sprintf(buffer, "%d", ol);
  set_arg(buffer);
  set_arg("nexthop");
  sprintf(buffer, "%s", iface);
  set_arg(buffer);
  set_arg("ipv4");
  sprintf(buffer, "%s",	nh);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  
  if (il){
   //./mpls ilm add label gen 34 labelspace 0
   alloc_args();
   set_arg("ilm");
   set_arg("add");
   set_arg("label");
   set_arg("gen");
   sprintf(buffer, "%d", il);
   set_arg(buffer);
   set_arg("labelspace");
   sprintf(buffer, "%d", 0);  //default the labelspace value =0
   set_arg(buffer);
   set_arg("proto");// Testing for VPLS packet ...This need to be marked.
   set_arg("packet");//Testing for VPLS packet ...This need to be marked.
   mpls_action(arg_index, args);
   free_args();
   
   //./mpls xc add ilm_label gen 200 ilm_labelspace 0 nhlfe_key 0x3
   alloc_args();
   set_arg("xc");
   set_arg("add");
   set_arg("ilm_label");
   set_arg("gen");
   sprintf(buffer, "%d", il);
   set_arg(buffer);
   set_arg("ilm_labelspace");
   sprintf(buffer, "%d", 0);  //default the labelspace value =0
   set_arg(buffer);
   set_arg("nhlfe_key");
   sprintf(buffer, "%d", res); 
   set_arg(buffer);
   mpls_action(arg_index, args);
   free_args();
	}
	printf("DEBUG(MPLSD):add_label_to_label_tc exit. res:%d.\n",res);
  return res;
  
}

int del_label_to_label(int il, int okey){
 /* int res;
  alloc_args();
  //printf("out label key %08x\n", okey);
  set_arg("-DO");
  sprintf(buffer, "%d", okey);
  set_arg(buffer);
  mpls_action(arg_index, args);
  free_args();
  alloc_args();
  set_arg("-DI");
  sprintf(buffer, "gen:%d:0", il);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):del_label_to_label enter.\n");
   int res=-1;
 
   //mpls ilm delete label gen 34 labelspace 0
   alloc_args();
   set_arg("ilm");
   set_arg("delete");
   set_arg("label");
   set_arg("gen");
   sprintf(buffer, "%d", il);
   set_arg(buffer);
   set_arg("labelspace");
   sprintf(buffer, "%d", 0);  //default the labelspace value =0
   set_arg(buffer);
   set_arg("proto");// Testing for VPLS packet ...This need to be marked.
   set_arg("packet");//Testing for VPLS packet ...This need to be marked.
   res=mpls_action(arg_index, args);
   free_args();
    //mpls nhlfe delete key <key>
   alloc_args();
   set_arg("nhlfe");
   set_arg("delete");
   set_arg("key");

   sprintf(buffer, "%d", okey);
   set_arg(buffer);
   res=mpls_action(arg_index, args);
  
   free_args();
   printf("DEBUG(MPLSD):del_label_to_label exit. res:%d.\n",res);
   return res;
}
//not used on rsvpd 
int add_label_to_ipv4_exp(int il, int iexp){
 /* int res;
  alloc_args();
  assert(iexp<8);
  set_arg("-AI");
  sprintf(buffer, "gen:%d:0", il);
  set_arg(buffer);
  set_arg("-i");
  sprintf(buffer, "pop:exp2ds:%s:peek", EXP2DSMAP);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
}

int add_label_to_ipv4_setdscp(int il){
 /* int res;
  alloc_args();
  set_arg("-AI");
  sprintf(buffer, "gen:%d:0", il);
  set_arg(buffer);
  set_arg("-i");
//sprintf(buffer, "pop:exp2ds:%s:peek", EXP2DSMAP);
  sprintf(buffer, "pop:peek");
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):add_label_to_ipv4_setdscp enter.\n");
  //./mpls ilm add label gen 200 labelspace 0 instructions pop exp2ds 0 0 1 0x2e 2 0xa 3 0xc 4 0x12 5 0x14 6 0x1a 7 0x1c peek
	 int res;
	 char exp2ds_buf[100]={0};
   char *delim=":";
   char *p;
	 alloc_args();
   set_arg("ilm");
   set_arg("add");
   set_arg("label");
   set_arg("gen");
   sprintf(buffer, "%d", il);
   set_arg(buffer);
   set_arg("labelspace");
   sprintf(buffer, "%d", 0);  //default the labelspace value =0
   set_arg(buffer);
   set_arg("proto");// Testing for VPLS packet ...This need to be marked.
   set_arg("packet");//Testing for VPLS packet ...This need to be marked.
   set_arg("instructions");
   set_arg("pop");
   set_arg("exp2ds");
   
   sprintf(exp2ds_buf,"%s",EXP2DSMAP);
	 sprintf(buffer,"%s",strtok(exp2ds_buf,delim));
	 set_arg(buffer);
	 while(p=strtok(NULL,delim)){
  	 sprintf(buffer,"%s",p);
		 set_arg(buffer);
   }
   
   set_arg("peek");
   res=mpls_action(arg_index, args);
   free_args();
   printf("DEBUG(MPLSD):add_label_to_ipv4_setdscp exit. res:%d.\n",res);
   return res;
}

int add_label_to_ipv4(int il){
 /* int res;
  alloc_args();
  set_arg("-AI");
  sprintf(buffer, "gen:%d:0", il);
  set_arg(buffer);
  set_arg("-i");
  sprintf(buffer, "pop:peek");
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
   printf("DEBUG(MPLSD):add_label_to_ipv4 enter.\n");
 // ./mpls ilm add label gen 300 labelspace 0 instructions pop peek 
 	 int res;
	 alloc_args();
   set_arg("ilm");
   set_arg("add");
   set_arg("label");
   set_arg("gen");
   sprintf(buffer, "%d", il);
   set_arg(buffer);
   set_arg("labelspace");
   sprintf(buffer, "%d", 0);  //default the labelspace value =0
   set_arg(buffer);
   set_arg("proto");// Testing for VPLS packet ...This need to be marked.
   set_arg("packet");//Testing for VPLS packet ...This need to be marked.
   set_arg("instructions");
   set_arg("pop");
   set_arg("peek");
   res=mpls_action(arg_index, args);
   free_args();
   printf("DEBUG(MPLSD):add_label_to_ipv4 exit. res:%d.\n",res);
   return res;
}

int del_label_to_ipv4(int il){
 /* int res;
  alloc_args();
  set_arg("-DI");
  sprintf(buffer, "gen:%d:0", il);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):del_label_to_ipv4 enter.\n");
 // ./mpls ilm delete label gen 300 labelspace 0
   int res;
	 alloc_args();
   set_arg("ilm");
   set_arg("delete");
   set_arg("label");
   set_arg("gen");
   sprintf(buffer, "%d", il);
   set_arg(buffer);
   set_arg("labelspace");
   sprintf(buffer, "%d", 0);  //default the labelspace value =0
   set_arg(buffer);
   set_arg("proto");// Testing for VPLS packet ...This need to be marked.
   set_arg("packet");//Testing for VPLS packet ...This need to be marked.
   res=mpls_action(arg_index, args);
   free_args();
   printf("DEBUG(MPLSD):del_label_to_ipv4 exit. res:%d.\n",res);
   return res;
}
//add by here . To suitable for ldpd/impl_mpls.c file
//not used on rsvpd
int add_label_to_ipv4_labelspace(int il,int labelspace){
  /*int res;
  alloc_args();
  set_arg("-AI");
  sprintf(buffer, "gen:%d:%d", il,labelspace);
  set_arg(buffer);
  set_arg("-i");
  sprintf(buffer, "pop:peek");
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
}
//not used on rsvpd
int del_label_to_ipv4_labelspace(int il,int labelspace){
 /* int res;
  alloc_args();
  set_arg("-DI");
  sprintf(buffer, "gen:%d:%d", il,labelspace);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
}

//end by here


int create_tunnel_interface(char* mplsiface){
 /* int res;
  alloc_args();
  set_arg("-AT");
  sprintf(buffer, "%s", mplsiface);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
   printf("DEBUG(MPLSD):create_tunnel_interface enter.\n");
  //./mpls tunnel add dev mpls100 
  int res;
  alloc_args();
  set_arg("tunnel");
  set_arg("add");
  set_arg("dev");
  sprintf(buffer, "%s", mplsiface);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):create_tunnel_interface exit. res:%d.\n",res);
  return res;
}


int map_label_tunnel(int labelref, char* mplsiface){
 /* int res;
  alloc_args();
  set_arg("-B");
  set_arg("-T");
  sprintf(buffer, "%s", mplsiface);
  set_arg(buffer);
  set_arg("-O");
  //  sprintf(buffer, "key:0x%x", labelref);
  sprintf(buffer, "%d", labelref);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):map_label_tunnel enter Name:%s.\n",mplsiface);
  //./mpls tunnel set dev mpls0 nhlfe 0x02 
  int res;
  alloc_args();
  set_arg("tunnel");
  set_arg("set");
  set_arg("dev");
  sprintf(buffer, "%s", mplsiface);
  set_arg(buffer);
  set_arg("nhlfe");
  sprintf(buffer, "%d", labelref);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):map_label_tunnel exit. res:%d.\n",res);
  return res;
}

int del_tunnel(char* mplsiface){
/*  int res;
  alloc_args();
  set_arg("-DT");
  sprintf(buffer, "%s", mplsiface);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;*/
  printf("DEBUG(MPLSD):del_tunnel enter.\n");
  //./mpls tunnel delete mpls100
  int res;
  alloc_args();
  set_arg("tunnel");
  set_arg("delete");
  set_arg("dev");
  sprintf(buffer, "%s", mplsiface);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):del_tunnel exit. res:%d.\n",res);
  return res;
}
//New functions to support VPLS technology capability
int add_label_to_packet(int il,int labelspace){
	printf("DEBUG(MPLSD):add_label_to_packet enter.\n");
//./mpls ilm add label gen 601 labelspace 0 proto packet
 	 int res;
	 alloc_args();
   set_arg("ilm");
   set_arg("add");
   set_arg("label");
   set_arg("gen");
   sprintf(buffer, "%d", il);
   set_arg(buffer);
   set_arg("labelspace");
   sprintf(buffer, "%d", labelspace);
   set_arg(buffer);
   set_arg("proto");
   set_arg("packet");
   res=mpls_action(arg_index, args);
   free_args();
   printf("DEBUG(MPLSD):add_label_to_packet exit. res:%d.\n",res);
   return res;
}

int add_otunnel_packet(const char* iface){
	printf("DEBUG(MPLSD):add_otunnel_packet enter.\n");
	//./mpls nhlfe add key 0 instructions nexthop mpls100 packet
 	int res;
  alloc_args();
  set_arg("nhlfe");
  set_arg("add");
  set_arg("key");
  sprintf(buffer, "%d", 0);
  set_arg(buffer);
  set_arg("instructions");
  set_arg("nexthop");
  sprintf(buffer, "%s", iface);
  set_arg(buffer);
  set_arg("packet");

  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):add_otunnel_packet exit. res:%d.\n",res);
  return res;
}

int add_label_stack(int nhlfe_key,int olabel){
	printf("DEBUG(MPLSD):add_label_stack enter.\n");
	//./mpls nhlfe add key 0 instructions push gen 100 forward 0x2
 	int res;
  alloc_args();
  set_arg("nhlfe");
  set_arg("add");
  set_arg("key");
  sprintf(buffer, "%d", 0);
  set_arg(buffer);
  set_arg("instructions");
  set_arg("push");
  set_arg("gen");
  sprintf(buffer, "%d", olabel);
  set_arg(buffer);
  set_arg("forward");
	sprintf(buffer, "%d", nhlfe_key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  printf("DEBUG(MPLSD):add_label_stack exit. res:%d.\n",res);
  return res;
}
//int bind_olabel();

//end for VPLS technology capability

int show_mplsd_labelspace(){
	int res;
	alloc_args();
  set_arg("labelspace");
  set_arg("show");
  res = mpls_action(arg_index, args);
  free_args();
	return res;
}

int show_mplsd_xc(){
	int res;
	alloc_args();
  set_arg("xc");
  set_arg("show");
  res = mpls_action(arg_index, args);
  free_args();
	return res;
}

int show_mplsd_ilm(){
	int res;
	alloc_args();
  set_arg("ilm");
  set_arg("show");
  res = mpls_action(arg_index, args);
  free_args();
	return res;
}

int show_mplsd_nhlfe(){
	int res;
	alloc_args();
  set_arg("nhlfe");
  set_arg("show");
  res = mpls_action(arg_index, args);
  free_args();
	return res;
}
