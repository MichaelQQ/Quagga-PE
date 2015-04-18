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
#include "mplsadm.h"
#include "ds_mpls.h"

/* PVH interface with mplsadm. 
   in mplsadm.c:
     change main() to mpls_action()
     set optind=1 before call to getopt()
*/
//add by here
/* to return key by unix socket*/
//#include "zebra.h"
//#include "command.h"
//#include "log.h" 
//end by here


#define MAXARGS 25
int arg_index = 0;
char** args;
char buffer[1024];

void alloc_args(void){
  arg_index = 1;
  args = (char**) malloc (MAXARGS*sizeof(char*));
  args[0] = (char*) malloc(sizeof("mplsadm"));
  sprintf(args[0], "mplsadm");  
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
  int res;
  alloc_args();
  set_arg("-L");
  sprintf(buffer, "%s:%d", interface, label_space_no);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}

int del_label_space(const char* interface){
  int res;
  alloc_args();
  set_arg("-L");
  sprintf(buffer, "%s:%d", interface, -1);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}

int add_fec_to_label(int table, const char* fec, int label, int exp, 
		     const char* iface, const char* nh,struct vty *vty){
  int res;
  alloc_args();
  assert(exp<8);
  set_arg("-ABO");
  sprintf(buffer, "gen:%d:%s:ipv4:%s", label,  iface, nh);
  set_arg("-f");
  sprintf(buffer, "%s",fec);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
 // printf("Get key value : %d\n",res);
  //vty->node = MPLSADMD_NODE;
 // vty_out (vty,"KEY %s", VTY_NEWLINE);
  free_args();
  return res;
}


int add_olabel(int label, const char* iface, const char* nh){
 int res;
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
 return res; // this should the key!
}

int add_olabel_exp(int label, int exp, const char* iface, const char* nh){
  int res;
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
 return res;
} 

int add_olabel_tc(int label, int tc, const char* iface, const char* nh){
  int res;
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
 return res;
} 

int add_olabel_tcindex(int label, const char* iface, const char* nh){
  int res;
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
 return res;
} 


int del_olabel(int key){ 
 int res;
  alloc_args();
  set_arg("-DO");
  sprintf(buffer, "%d", key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}

int bind_olabel(int label, int key){ 
 int res;
  alloc_args();
  set_arg("-BI");
  sprintf(buffer, "gen:%d:0", label);
  set_arg(buffer);
  set_arg("-O");
  sprintf(buffer, "%d", key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}
//add by here . To suitable for ldpd/impl_mpls.c file
int unbind_olabel(int label, int key){
 int res;
  alloc_args();
  set_arg("-UI");
  sprintf(buffer, "gen:%d:0", label);
  set_arg(buffer);
  set_arg("-O");
  sprintf(buffer, "%d", key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}
//Establish a (part of a) label switch path
//referece http://perso.enst.fr/~casellas/mpls-linux/ch02s02.html

int bind_olabel_labelspace(int inlabel,int labelspace, int key){ 
 int res;
  alloc_args();
  set_arg("-BI");
  sprintf(buffer, "gen:%d:%d", inlabel,labelspace);
  set_arg(buffer);
  set_arg("-O");
  sprintf(buffer, "%d", key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}
int unbind_olabel_labelspace(int inlabel,int labelspace, int key){ 
 int res;
  alloc_args();
  set_arg("-UI");
  sprintf(buffer, "gen:%d:%d", inlabel,labelspace);
  set_arg(buffer);
  set_arg("-O");
  sprintf(buffer, "%d", key);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}
//end by here
int del_ilabel(int label, int exp){
 int res;
  alloc_args();
  assert(exp<8);
  set_arg("-DI");
  sprintf(buffer, "gen:%d:0", label);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}

int del_fec_to_label(int table, const char* fec, int label, int exp, 
		     const char* iface){
  int res;
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
  return res;
}

int unbind_fec_to_label(int table, const char* fec, int label, int exp, 
			const char* iface){
  int res;
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
  return res;
}

int add_label_to_label(int il, int ol, const char* iface, 
		       const char* nh){
  int res;
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
 return res; // return key of olabel here
}

int add_label_to_label_tc(int il, int ol, int tc, const char* iface, 
			  const char* nh){
  int res;
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
  return res; // return key of olabel here
}

int del_label_to_label(int il, int okey){
  int res;
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
  return res;
}

int add_label_to_ipv4_exp(int il, int iexp){
  int res;
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
  return res;
}

int add_label_to_ipv4_setdscp(int il){
  int res;
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
  return res;
}

int add_label_to_ipv4(int il){
  int res;
  alloc_args();
  set_arg("-AI");
  sprintf(buffer, "gen:%d:0", il);
  set_arg(buffer);
  set_arg("-i");
  sprintf(buffer, "pop:peek");
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}

int del_label_to_ipv4(int il){
  int res;
  alloc_args();
  set_arg("-DI");
  sprintf(buffer, "gen:%d:0", il);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}
//add by here . To suitable for ldpd/impl_mpls.c file
int add_label_to_ipv4_labelspace(int il,int labelspace){
  int res;
  alloc_args();
  set_arg("-AI");
  sprintf(buffer, "gen:%d:%d", il,labelspace);
  set_arg(buffer);
  set_arg("-i");
  sprintf(buffer, "pop:peek");
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}

int del_label_to_ipv4_labelspace(int il,int labelspace){
  int res;
  alloc_args();
  set_arg("-DI");
  sprintf(buffer, "gen:%d:%d", il,labelspace);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}

//end by here


int create_tunnel_interface(char* mplsiface){
  int res;
  alloc_args();
  set_arg("-AT");
  sprintf(buffer, "%s", mplsiface);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}


int map_label_tunnel(int labelref, char* mplsiface){
  int res;
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
  return res;
}

int del_tunnel(char* mplsiface){
  int res;
  alloc_args();
  set_arg("-DT");
  sprintf(buffer, "%s", mplsiface);
  set_arg(buffer);
  res = mpls_action(arg_index, args);
  free_args();
  return res;
}

