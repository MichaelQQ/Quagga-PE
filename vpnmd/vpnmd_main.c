#include "zebra.h"

#include "thread.h"
struct thread_master *master = NULL;	/* Master of threads. */

#include "vpnmd_main.h"
//vpn manager include header file
#include "vpnm.h"
#include <pthread.h>
char config_default[] = SYSCONFDIR VPNMD_DEFAULT_CONFIG;
char *config_file = NULL;

char *vty_addr = NULL;
int vty_port = VPNMD_VTY_PORT;

char pid_file[] = PATH_VPNMD_PID;

#include "memory.h"
#include "command.h"
#include "vty.h"
#include "log.h"


//end vpn manager
/* SIGHUP handler. */

void sighup ()
{
  zlog_info ("SIGHUP received");
  zlog_info ("vpnmd restarting!");
  vty_read_config (config_file, config_default);
  vty_serv_sock (vty_addr, vty_port, VPNM_VTYSH_PATH);
}

void sigint ()
{
  zlog_info ("Terminating on signal");
  exit (0); 
}

void sigusr1 () 
{
  zlog_rotate (NULL); 
}

#include "sigevent.h"
struct quagga_signal_t vpnmd_signals[] = 
{
 { .signal = SIGHUP,
   .handler = &sighup,
 },
 { .signal = SIGINT,
   .handler = &sigint,
 },
 {  .signal = SIGTERM,
   .handler = &sigint,
 },
 { .signal = SIGUSR1,
   .handler = &sigusr1,
 },
} ;

#include "version.h"
static void usage (char *progname, int status) /* Help information display. */ {
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else {
    printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages vpnmd related configuration.\n\n\
-d, --daemon       Runs in daemon mode\n\
-l, --log_mode     Set verbose log mode flag\n\
-f, --config_file  Set configuration file name\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\n\
-h, --help         Display this help and exit\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS); }
  exit (status); }

#include "getopt.h"
struct option longopts[] =
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "log_mode",    no_argument,       NULL, 'l'},
  { "config_file", required_argument, NULL, 'f'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "user",        required_argument, NULL, 'u'},
  { "group",       required_argument, NULL, 'g'},
  { "version",     no_argument,       NULL, 'v'},
  { "help",        no_argument,       NULL, 'h'},
  { 0 }
};

#include "privs.h"
/* vpnmd privileges */
zebra_capabilities_t _caps_p [] =
{
  ZCAP_NET_RAW,
  ZCAP_BIND
};

struct zebra_privs_t vpnmd_privs =
{
#ifdef QUAGGA_USER
 .user = QUAGGA_USER,
#endif
#ifdef QUAGGA_GROUP
 .group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
 .vty_group = VTY_GROUP,
#endif
 .caps_p = _caps_p,
 .cap_num_p = 2,
 .cap_num_i = 0
};

/* Main startup routine. */
int main (int argc, char **argv)
{
  char *p; char *progname;
  int daemon_mode = 0;
  int log_mode = 0;
  struct thread thread;

  /* Set umask before anything for security */
  umask (0027); 
  /* preserve my name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]); 

  zlog_default = openzlog (progname, ZLOG_VPNMD,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

while (1) {
      int opt;
      opt = getopt_long (argc, argv, "dlf:A:P:u:g:vh", longopts, 0);

      if (opt == EOF)
	break;
      switch (opt) 
	{case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'l':
	  log_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'A':
	  vty_addr = optarg;
        break;
	case 'P':
	  vty_port = atoi (optarg);
	  break;
case 'u': vpnmd_privs.user = optarg; break;
case 'g': vpnmd_privs.group = optarg; break;
	case 'v':
	  print_version (progname);
	  exit (0);
	  break;
	case 'h':
	  usage (progname, 0);
	  break;
	default:
	  usage (progname, 1);
	  break;
	} }

 /* Prepare master thread. */
  master = thread_master_create();

 /* Library initialization. */
  zprivs_init(&vpnmd_privs);
//signal_init();
signal_init (master, array_size(vpnmd_signals), vpnmd_signals);
  cmd_init(1);
  vty_init(master);
  memory_init();

  /* VPNMD related initialization. */
  vpnmd_init();
  
  vpnmd_zclient_init();

  /* Sort all installed commands. */
  sort_node ();

  /* Configuration file read */
  vty_read_config (config_file, config_default);

  /* Daemonize. */
  if (daemon_mode) daemon (0, 0);

  /* Pid file create. */
  pid_output (pid_file);

  /* Create VTY socket */
  vty_serv_sock (vty_addr, vty_port, VPNM_VTYSH_PATH);

  /* Print banner. */
  zlog_notice ("VPNMD %s starting: vty@%d", QUAGGA_VERSION, vty_port);
  
  /* Execute each thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}

