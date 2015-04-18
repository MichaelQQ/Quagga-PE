#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h> 
#include "connect_daemon.h"
#include "vty.h"

int test(void);


/* Making connection to protocol daemon. */
int
vtysh_connect (struct vtysh_client *vclient, const char *path)
{
  int ret;
  int sock, len;
  struct sockaddr_un addr;
  struct stat s_stat;
  uid_t euid;
  gid_t egid;

  memset (vclient, 0, sizeof (struct vtysh_client));
  vclient->fd = -1;

  /* Stat socket to see if we have permission to access it. */
  euid = geteuid();
  egid = getegid();
  ret = stat (path, &s_stat);
  if (ret < 0 && errno != ENOENT)
    {
      fprintf  (stderr, "vtysh_connect(%s): stat = %s\n", 
		path, strerror(errno)); 
      exit(1);
    }
  
  if (ret >= 0)
    {
      if (! S_ISSOCK(s_stat.st_mode))
	{
	  fprintf (stderr, "vtysh_connect(%s): Not a socket\n",
		   path);
	  exit (1);
	}
      
    }

  sock = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
#ifdef DEBUG
      fprintf(stderr, "vtysh_connect(%s): socket = %s\n", path,
	      strerror(errno));
#endif /* DEBUG */
      return -1;
    }

  memset (&addr, 0, sizeof (struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, path, strlen (path));
#ifdef HAVE_SUN_LEN
  len = addr.sun_len = SUN_LEN(&addr);
#else
  len = sizeof (addr.sun_family) + strlen (addr.sun_path);
#endif /* HAVE_SUN_LEN */

  ret = connect (sock, (struct sockaddr *) &addr, len);
  if (ret < 0)
    {
#ifdef DEBUG
      fprintf(stderr, "vtysh_connect(%s): connect = %s\n", path,
	      strerror(errno));
#endif /* DEBUG */
      close (sock);
      return -1;
    }
  vclient->fd = sock;

  return 0;
}


void
vclient_close (struct vtysh_client *vclient)
{
  if (vclient->fd > 0)
    close (vclient->fd);
  vclient->fd = -1;
}

int
vtysh_client_execute (struct vtysh_client *vclient, const char *line, FILE *fp)
{
  int ret;
  char buf[1001];
  int nbytes;
  int i; 
  int numnulls = 0;
  if (vclient->fd < 0)
    return CMD_SUCCESS;

  ret = write (vclient->fd, line, strlen (line) + 1);
  if (ret <= 0)
    {
      vclient_close (vclient);
      return CMD_SUCCESS;
    }
	
  while (1)
    {
      nbytes = read (vclient->fd, buf, sizeof(buf)-1);
      if (nbytes <= 0 && errno != EINTR)
	{
	  vclient_close (vclient);
	  return CMD_SUCCESS;
	}

      if (nbytes > 0)
	{
	  buf[nbytes] = '\0';
	  fprintf (fp, "%s", buf);
	  fflush (fp);
	  
	  /* check for trailling \0\0\0<ret code>, 
	   * even if split across reads 
	   * (see lib/vty.c::vtysh_read)
	   */
          if (nbytes >= 4) 
            {
              i = nbytes-4;
              numnulls = 0;
            }
          else
            i = 0;
          
          while (i < nbytes && numnulls < 3)
            {
              if (buf[i++] == '\0')
                numnulls++;
              else
                {
                  numnulls = 0;
                  break;
                }
            }

          /* got 3 or more trailling nulls? */
          if (numnulls >= 3)
             return (atoi(buf));
            //return (buf[nbytes-1]);
	}
    }
  assert (1);
}


int connect_daemon(int index){

switch(index){
	case VTYSH_INDEX_ZEBRA:
		//printf("connect to zebra .\n");
		vtysh_connect(
		&vtysh_client[VTYSH_INDEX_ZEBRA], ZEBRA_VTYSH_PATH);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_ZEBRA], "enable", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_ZEBRA], "configure terminal", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_ZEBRA], "router zebra", stdout);
		break;
	case VTYSH_INDEX_BGP:
		//printf("connect to bgp .\n");
		vtysh_connect(
		&vtysh_client[VTYSH_INDEX_BGP], BGP_VTYSH_PATH);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_BGP], "enable", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_BGP], "configure terminal", stdout);
		//Bgp daemon have special "router bgp ..." ,so those code need to extra write. 
		break;
	case VTYSH_INDEX_LDP:
		//printf("connect to ldp .\n");
		vtysh_connect(
		&vtysh_client[VTYSH_INDEX_LDP], LDP_VTYSH_PATH);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_LDP], "enable", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_LDP], "configure terminal", stdout);
		break;
	case VTYSH_INDEX_MPLSADMD:
		//printf("connect to mplsadmd .\n");
		vtysh_connect(
		&vtysh_client[VTYSH_INDEX_MPLSADMD], MPLSADM_VTYSH_PATH);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_MPLSADMD], "enable", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_MPLSADMD], "configure terminal", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_MPLSADMD], "router mplsadmd", stdout);
		break;
	case VTYSH_INDEX_LMD:
		//printf("connect to lmd .\n");
		vtysh_connect(
		&vtysh_client[VTYSH_INDEX_LMD], LM_VTYSH_PATH);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_LMD], "enable", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_LMD], "configure terminal", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_LMD], "router lmd", stdout);
		break;
	case VTYSH_INDEX_VPNMD:
	//	printf("connect to vpn manager .\n");
		vtysh_connect(
		&vtysh_client[VTYSH_INDEX_VPNMD], VPNM_VTYSH_PATH);/*
		printf("enter connect mode.\n");
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_VPNMD], "enable", stdout);
		printf("enter enable mode.\n");
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_VPNMD], "configure terminal", stdout);
		printf("enter configure terminal mode.\n");
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_VPNMD], "router vpnmd", stdout);
		printf("enter router vpnmd mode.\n");*/
		break;
	case VTYSH_INDEX_RSVPD:
		//printf("connect to label manager .\n");
		vtysh_connect(
		&vtysh_client[VTYSH_INDEX_RSVPD], RSVP_VTYSH_PATH);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_RSVPD], "enable", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_RSVPD], "configure terminal", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_RSVPD], "router rsvpd", stdout);
		break;
	case VTYSH_INDEX_BRCTLD:
		vtysh_connect(
		&vtysh_client[VTYSH_INDEX_BRCTLD], BRCTL_VTYSH_PATH);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_BRCTLD], "enable", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_BRCTLD], "configure terminal", stdout);
		vtysh_client_execute(
		&vtysh_client[VTYSH_INDEX_BRCTLD], "router brctld", stdout);
		break;
	default:
		printf("You connect to other daemon.(Those code isn't ready for use.).\n");
		break;
}
	return 0;
/*
vtysh_connect(
&vtysh_client[VTYSH_INDEX_LMD], LMD_VTYSH_PATH);
vtysh_client_execute(
&vtysh_client[VTYSH_INDEX_LMD], "enable", stdout);
vtysh_client_execute(
&vtysh_client[VTYSH_INDEX_LMD], "configure terminal", stdout);
vtysh_client_execute(
&vtysh_client[VTYSH_INDEX_LMD], "router lmd", stdout);*/

}
int exit_daemon(int index){

switch(index){
	case VTYSH_INDEX_ZEBRA:
		//printf("exit to zebra .\n");
		vclient_close(&vtysh_client[VTYSH_INDEX_ZEBRA]);
		break;
	case VTYSH_INDEX_BGP:
		//printf("exit to bgp .\n");
		vclient_close(&vtysh_client[VTYSH_INDEX_BGP]);
		//Bgp daemon have special "router bgp ..." ,so those code need to extra write. 
		break;
	case VTYSH_INDEX_LDP:
		//printf("exit ldp .\n");
		vclient_close(&vtysh_client[VTYSH_INDEX_LDP]);
		break;
	case VTYSH_INDEX_MPLSADMD:
		//printf("exit mplsadmd .\n");
		vclient_close(&vtysh_client[VTYSH_INDEX_MPLSADMD]);
		break;
	case VTYSH_INDEX_LMD:
		//printf("exit lmd .\n");
		vclient_close(&vtysh_client[VTYSH_INDEX_LMD]);
		break;
	case VTYSH_INDEX_VPNMD:
		//printf("exit vpn manager .\n");
		vclient_close(&vtysh_client[VTYSH_INDEX_VPNMD]);
		break;
	case VTYSH_INDEX_RSVPD:
		//printf("exit label manager .\n");
		vclient_close(&vtysh_client[VTYSH_INDEX_RSVPD]);
		break;
	case VTYSH_INDEX_BRCTLD:
		vclient_close(&vtysh_client[VTYSH_INDEX_BRCTLD]);
		break;
	default:
		printf("You connect to other daemon.(Those code isn't ready for use.).\n");
		break;
}
	return 0;
/*
vtysh_client_execute(
&vtysh_client[VTYSH_INDEX_LMD], "exit", stdout);
vtysh_client_execute(
&vtysh_client[VTYSH_INDEX_LMD], "exit", stdout);*/

}

// example : To talk with mplsadmd
int test(void){
//connect to mplsadmd deamen
vtysh_connect(
&vtysh_client[VTYSH_INDEX_MPLSADMD], MPLSADM_VTYSH_PATH);
vtysh_client_execute(
&vtysh_client[VTYSH_INDEX_MPLSADMD], "enable", stdout);
vtysh_client_execute(
&vtysh_client[VTYSH_INDEX_MPLSADMD], "configure terminal", stdout);
vtysh_client_execute(
&vtysh_client[VTYSH_INDEX_MPLSADMD], "router mplsadmd", stdout);

int retKey=0;
retKey=vtysh_client_execute(
&vtysh_client[VTYSH_INDEX_MPLSADMD], "add_fec_to_label table 5 fec 140.123.107.122 label 222 exp 2 iface eth0 nh 140.123.107.43", stdout);
printf("KEY_KEY value :%d\n",retKey);
vclient_close(
&vtysh_client[VTYSH_INDEX_MPLSADMD] );

return 0; 
}
