#define VTYSH_INDEX_ZEBRA 0
#define VTYSH_INDEX_RIP   1
#define VTYSH_INDEX_RIPNG 2
#define VTYSH_INDEX_OSPF  3
#define VTYSH_INDEX_OSPF6 4
#define VTYSH_INDEX_BGP   5
#define VTYSH_INDEX_ISIS  6
#define VTYSH_INDEX_LDP   7
#define VTYSH_INDEX_MPLSADMD   8
#define VTYSH_INDEX_LMD   9
#define VTYSH_INDEX_VPNMD 10
#define VTYSH_INDEX_BRCTLD 11
#define VTYSH_INDEX_RSVPD 12
#define VTYSH_INDEX_MAX   13

/*#define ZEBRA_VTYSH_PATH	"/var/run/zebra.vty"
#define LDP_VTYSH_PATH 		"/var/run/ldpd.vty"
#define MPLSADMD_VTYSH_PATH "/var/run/mplsadmd.vty"  
#define LMD_VTYSH_PATH 		"/var/run/LMD.vty"
#define VPNMD_VTYSH_PATH 	"/var/run/vpnmd.vty"
#define RSVPD_VTYSH_PATH 	"/var/run/rsvpd.vty"
#define BRCTLD_VTYSH_PATH "/var/run/brctld.vty"
*/

//#define BGP_VTYSH_PATH "/var/run/bgpd.vty"
#define CMD_SUCCESS 0
#define DEBUG 1
//#define safe_strerror strerror



/* VTY shell client structure. */
struct vtysh_client
{
  int fd;
} vtysh_client[VTYSH_INDEX_MAX];


int vtysh_connect (struct vtysh_client *vclient, const char *path);
void vclient_close (struct vtysh_client *vclient);
int vtysh_client_execute (struct vtysh_client *vclient, const char *line, FILE *fp);

//connect to mplsadmd
int connect_daemon(int index);
//exit to mplsadmd
int exit_daemon(int index);


