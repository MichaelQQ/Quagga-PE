#define VPNMD_DEFAULT_CONFIG "vpnmd.conf"
#define VPNMD_VTY_PORT 2630
#define VPN_M_PORT 10003

void vpnmd_init(void);
void vpnmd_zclient_init(void);

//socket 
struct vpnm_sock{
int fd; //socket file descrpitor
struct sockaddr_in from;
socklen_t len;
};
typedef struct vpnm_sock * vpnm_sock_handle;
vpnm_sock_handle vpnm_socket_create_udp(); 
struct vpnm_sock *vpnm_sock_get();
//end socket 




