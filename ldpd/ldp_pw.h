
void establish_ldp_session_here(unsigned long dst_ip);
void stop_ldp_session_here(unsigned long dst_ip);
int verify_vc_state(struct vty *vty,int vc_type,int vpn_id,int label,unsigned long dst_ip);
int withdraw_pw_here(int vc_type,int vpn_id,int label,unsigned long dst_ip);
int release_pw_here(int vc_type,int vpn_id,int label,unsigned long dst_ip);
void send_label_mapping_here(ldp_global *g, ldp_adj *a, u_int vpn_id, struct in_addr ip);
//void withdraw_pw_process(ldp_global *g, ldp_adj *a, u_int vpn_id, u_long label);