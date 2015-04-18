/* written by pim.vanheuven@intec.rug.ac.be
   basically interfacing with (slightly modified mplsadm)
   
   modified by giovanna piantanida

   This program is free software; you can redistribute it and/or 
   modify it under the terms of the GNU General Public License   
   as published by the Free Software Foundation; either version  
   2 of the License, or (at your option) any later version.      
*/


#ifndef LIBMPLS_H
#define LIBMPLS_H
//add by here
#include "zebra.h"
#include "command.h"
#include "log.h"
//end by here
extern char mplsadm_verbose;

int add_label_space(const char* interface, int label_space_no);
int del_label_space(const char* interface);

int add_fec_to_label(int table, const char* fec, int label, int exp, 
		     const char* iface, const char* nh,struct vty *vty);
int del_fec_to_label(int table, const char* fec, int label, int exp, 
		     const char* iface);

int add_olabel_exp(int label, int exp, const char* iface, const char* nh);
int add_olabel_tc(int label, int tc, const char* iface, const char* nh);
int add_olabel(int label, const char* iface, const char* nh);
int del_olabel(int labelkey);
int bind_olabel(int ilabel, int olabelkey);
//add by here . To suitable for ldpd/impl_mpls.c file
int unbind_olabel(int label, int key);
int bind_olabel_labelspace(int inlabel,int labelspace, int key);
int unbind_olabel_labelspace(int inlabel,int labelspace, int key);
//end by here

int unbind_fec_to_label(int table, const char* fec, int label, int exp, 
			const char* iface);

int add_label_to_label(int il, int ol, const char* iface, 
		       const char* nh);
int add_label_to_label_tc(int il, int ol, int tc, const char* iface, 
		       const char* nh);
int del_label_to_label(int ilabel, int okey);
int del_ilabel(int il, int iexp);

int add_label_to_ipv4(int il);
int add_label_to_ipv4_setdscp(int il);
int del_label_to_ipv4(int il);
//add by here . To suitable for ldpd/impl_mpls.c file
int add_label_to_ipv4_labelspace(int il,int labelspace);
int del_label_to_ipv4_labelspace(int il,int labelspace);
//end by here
int create_tunnel_interface(char* mplsiface);
int map_label_tunnel(int labelref, char* mplsiface);
int del_tunnel(char* mplsiface);
#endif
