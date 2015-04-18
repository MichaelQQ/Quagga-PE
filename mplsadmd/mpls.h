#ifndef MPLS_h
#define MPLS_H

#ifdef __cplusplus
extern "C" {
#endif
int mpls_action(int argc, char **argv);
char *get_mpls_table();
void flush_mpls_buffer();
#ifdef __cplusplus
}
#endif

extern int print_ilm(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);
extern int print_xc(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);
extern int print_labelspace(struct sockaddr_nl *who, struct nlmsghdr *n,
	void *arg);
extern int print_nhlfe(struct sockaddr_nl *who, struct nlmsghdr *n, void *arg);

#endif
