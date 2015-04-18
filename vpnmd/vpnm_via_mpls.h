/*
This code used to commnuicate with mplsd via VTY socket
*/

#ifndef _VPNM_VIA_MPLS_H_
#define _VPNM_VIA_MPLS_H_

int set_out_vclsp(const char *pw_if,int olabel,int nhlfe_key,int in_pw_state);
int set_in_vclsp(const char *pw_if,int ilabel,int out_pw_state);

int set_pw_data_plane(const char *pw_if,int olabel,int nhlfe_key,int ilabel);
int del_pw_data_plane();

#endif
