#include "zebra.h"
#include "command.h"
#include "log.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/un.h>
//#include "libmpls.h"
#include "rsvpd_vty.h"
#include <sys/ioctl.h>//+++

DEFUN(  rsvpd_vty_session,
        rsvpd_vty_session_cmd,
        "session WORD",
        "change session"
        "RSVPD protocol")
{
 vty->node = RSVPD_NODE;
//+++
 char *cp;
 char buf[255];
  sprintf(buf,"T%s ",argv[0]);
    int sockfd;
    int len;
    struct sockaddr_in address;
    int result;
/*  Create a socket for the client.  */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
/*  Name the socket, as agreed with the server.  */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(2205);
    len = sizeof(address);
/*  Now connect our socket to the server's socket.  */
    result = connect(sockfd, (struct sockaddr *)&address, len);
    write(sockfd,&buf,sizeof(buf));
    close(sockfd);
//+++
// vty_out (vty, "create session%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}
DEFUN(  rsvpd_vty_dest,
        rsvpd_vty_dest_cmd,
        "dest lsp tcp WORD",
        "dest lsp tcp ip_addr"
	"RSVPD protocol")
{
 vty->node = RSVPD_NODE;
//+++
 char *cp;
 char buf[255];
 sprintf(buf,"dest lsp tcp %s",argv[0]);
    int sockfd;
    int len;
    struct sockaddr_in address;
    int result;
/*  Create a socket for the client.  */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
/*  Name the socket, as agreed with the server.  */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(2205);
    len = sizeof(address);
/*  Now connect our socket to the server's socket.  */
    result = connect(sockfd, (struct sockaddr *)&address, len);
    write(sockfd,&buf,sizeof(buf));
    close(sockfd);
//+++
// vty_out (vty, "create session%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}
DEFUN(  rsvpd_vty_sender,
        rsvpd_vty_sender_cmd,
        "sender WORD",
        "sender ip_addr"
        "RSVPD protocol")
{
 vty->node = RSVPD_NODE;
//+++
 char *cp;
 char buf[255];
 sprintf(buf,"sender %s",argv[0]);
    int sockfd;
    int len;
    struct sockaddr_in address;
    int result;
/*  Create a socket for the client.  */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
/*  Name the socket, as agreed with the server.  */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(2205);
    len = sizeof(address);
/*  Now connect our socket to the server's socket.  */
    result = connect(sockfd, (struct sockaddr *)&address, len);
    write(sockfd,&buf,sizeof(buf));
    close(sockfd);
//+++
// vty_out (vty, "create session%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}
DEFUN(  rsvpd_vty_reserve,
        rsvpd_vty_reserve_cmd,
        "reserve WORD ff WORD",
        "reserve ip_addr ff ip_addr"
        "RSVPD protocol")
{
 vty->node = RSVPD_NODE;
//+++
 char *cp;
 char buf[255];
 sprintf(buf,"reserve %s ff %s",argv[0],argv[1]);
    int sockfd;
    int len;
    struct sockaddr_in address;
    int result;
/*  Create a socket for the client.  */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
/*  Name the socket, as agreed with the server.  */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(2205);
    len = sizeof(address);
/*  Now connect our socket to the server's socket.  */
    result = connect(sockfd, (struct sockaddr *)&address, len);
    write(sockfd,&buf,sizeof(buf));
    close(sockfd);
//+++
// vty_out (vty, "create session%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}
DEFUN(  rsvpd_vty_close_session,
        rsvpd_vty_close_session_cmd,
        "close dest",
        "close session"
        "RSVPD protocol")
{
 vty->node = RSVPD_NODE;
//+++
 char *cp;
 char buf[255];
 sprintf(buf,"close dest");
    int sockfd;
    int len;
    struct sockaddr_in address;
    int result;
/*  Create a socket for the client.  */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
/*  Name the socket, as agreed with the server.  */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(2205);
    len = sizeof(address);
/*  Now connect our socket to the server's socket.  */
    result = connect(sockfd, (struct sockaddr *)&address, len);
    write(sockfd,&buf,sizeof(buf));
    close(sockfd);
//+++
// vty_out (vty, "create session%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  vpnm_talk2_rsvpd,
        vpnm_talk2_rsvpd_cmd,
        "rsvp_cmd_type <0-3> arg0 WORD arg1 WORD arg2 WORD arg3 WORD",
        "VPN Manager talk to RSVPd via VTY SOCKET "
        "RSVPD protocol")
{
 vty->node = RSVPD_NODE;
printf("src:%s dest:%s lsp_id:%s",argv[1],argv[2],argv[3]);
    char buf[255],ch;
    int sockfd;
    int len;
    struct sockaddr_in address;
    int result;
/*  Create a socket for the client.  */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
/*  Name the socket, as agreed with the server.  */
    address.sin_family = AF_INET;
 switch(atoi(argv[0])){
 case SEND_PATH_MSG:
	address.sin_addr.s_addr = inet_addr(argv[1]);
	address.sin_port = htons(2205);
	len = sizeof(address);
	result = connect(sockfd, (struct sockaddr *)&address, len);
	//write to source
	sprintf(buf,"T%s ",argv[3]);
        write(sockfd,&buf,sizeof(buf));
	sprintf(buf,"dest lsp tcp %s/%s",argv[2],argv[3]);
	write(sockfd,&buf,sizeof(buf));
	sprintf(buf,"sender %s/%s",argv[1],argv[3]);
	write(sockfd,&buf,sizeof(buf));
	close(sockfd);
	//write to dest
    	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	address.sin_addr.s_addr = inet_addr(argv[2]);
        address.sin_port = htons(2205);
        len = sizeof(address);
        result = connect(sockfd, (struct sockaddr *)&address, len);
        sprintf(buf,"T%s ",argv[3]);
        write(sockfd,&buf,sizeof(buf));
        sprintf(buf,"dest lsp tcp %s/%s",argv[2],argv[3]);
        write(sockfd,&buf,sizeof(buf));
        sprintf(buf,"reserve %s ff %s/%s",argv[2],argv[1],argv[3]);
        write(sockfd,&buf,sizeof(buf));
        close(sockfd);
		//arg0 =src_ip
		//arg1 =dst_ip
		//arg2 =lsp_id
 break;
 case SEND_RESERVE_MSG:
	address.sin_addr.s_addr = inet_addr(argv[1]);
        address.sin_port = htons(2205);
        len = sizeof(address);
        result = connect(sockfd, (struct sockaddr *)&address, len);
        //write to source
	sprintf(buf,"T%s ",argv[3]);
	write(sockfd,&buf,sizeof(buf));
        sprintf(buf,"dest lsp tcp %s/%s",argv[1],argv[3]);
        write(sockfd,&buf,sizeof(buf));
	sprintf(buf,"reserve %s ff %s/%s",argv[1],argv[2],argv[3]);
        write(sockfd,&buf,sizeof(buf));
        close(sockfd);
 break;
 case WITHDRAW_TUNNEL:
	address.sin_addr.s_addr = inet_addr(argv[1]);
        address.sin_port = htons(2205);
        len = sizeof(address);
        result = connect(sockfd, (struct sockaddr *)&address, len);
        sprintf(buf,"T%s ",argv[3]);
        write(sockfd,&buf,sizeof(buf));
        sprintf(buf,"close");
        write(sockfd,&buf,sizeof(buf));
        close(sockfd);
	//write to dest
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
	address.sin_addr.s_addr = inet_addr(argv[2]);
        address.sin_port = htons(2205);
        len = sizeof(address);
        result = connect(sockfd, (struct sockaddr *)&address, len);
        sprintf(buf,"T%s ",argv[3]);
        write(sockfd,&buf,sizeof(buf));
        sprintf(buf,"close");
        write(sockfd,&buf,sizeof(buf));
        close(sockfd);
 break;
 case RELEASE_TUNNEL:
	address.sin_addr.s_addr = inet_addr(argv[2]);
        address.sin_port = htons(2205);
        len = sizeof(address);
        result = connect(sockfd, (struct sockaddr *)&address, len);
        sprintf(buf,"T%s ",argv[3]);
        write(sockfd,&buf,sizeof(buf));
        sprintf(buf,"close");
        write(sockfd,&buf,sizeof(buf));
        close(sockfd);
	//write to dest
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        address.sin_addr.s_addr = inet_addr(argv[1]);
        address.sin_port = htons(2205);
        len = sizeof(address);
        result = connect(sockfd, (struct sockaddr *)&address, len);
        sprintf(buf,"T%s ",argv[3]);
        write(sockfd,&buf,sizeof(buf));
        sprintf(buf,"close");
        write(sockfd,&buf,sizeof(buf));
        close(sockfd);
 break;
 default :
 break;
 }
 return CMD_SUCCESS;
}

DEFUN(  router_rsvpd,
        router_rsvpd_cmd,
        "router rsvpd",
        "Enable a routing process"
        "RSVPD protocol")
{
 vty->node = RSVPD_NODE;
 vty_out (vty, "Down to rsvpd node%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}

static struct cmd_node rsvpd_node =
{ RSVPD_NODE, "%s(config-rsvpd)# ", 1 };

void rsvpd_init(void)
{
install_node( &rsvpd_node, NULL );
install_default( RSVPD_NODE );

//install_element (VIEW_NODE,   &router_rsvpd_cmd);
//install_element (ENABLE_NODE, &router_rsvpd_cmd);
	install_element (CONFIG_NODE, &router_rsvpd_cmd);

        install_element( RSVPD_NODE, &rsvpd_vty_session_cmd);
	install_element( RSVPD_NODE, &rsvpd_vty_dest_cmd);
        install_element( RSVPD_NODE, &rsvpd_vty_sender_cmd);
        install_element( RSVPD_NODE, &rsvpd_vty_reserve_cmd);
        install_element( RSVPD_NODE, &rsvpd_vty_close_session_cmd);
	install_element( RSVPD_NODE, &vpnm_talk2_rsvpd_cmd);
/*
install_element( MPLSADMD_NODE,   &	rsvpd_vty_del_label_space_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpd_vty_add_fec_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpd_vty_del_fec_to_label_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpd_vty_map_label_tunnel_cmd	);
install_element( MPLSADMD_NODE,   &	rsvpd_vty_del_tunnel_cmd	);
*/
}

