#include <zebra.h>
#include <stdio.h>
#include <stdlib.h>

#include "version.h"
#include "getopt.h"
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"

#include "ldp.h"
#include "ldp_vty.h"
#include "ldp_zebra.h"
#include "ldp_interface.h"
#include "connect_daemon.h" //add by here

#define RX_BUF_LEN 512 //Add by timothy

/* Configuration filename and directory. */
char config_current[] = LDP_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR LDP_DEFAULT_CONFIG;

/* Command line options. */
struct option longopts[] =
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "log_mode",    no_argument,       NULL, 'l'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* Master of threads. */
struct thread_master *master = NULL;

/* Process ID saved for use by init system */
char *pid_file = PATH_LDPD_PID;

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages LDP related configuration.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-l, --log_mode     Set verbose log mode flag\n\
-h, --help         Display this help and exit\n\
-P, --vty_port     Set vty's port number\n\
-A, --vty_addr     Set vty's bind address\n\
-v, --version      Print program version\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }

  exit (status);
}

/* SIGHUP handler. */
void 
sighup (int sig)
{
  zlog_info ("SIGHUP received");

 /* Reload of config file. */
}

/* SIGINT handler. */
void
sigint (int sig)
{
  zlog_info ("Terminating on signal");

  exit (0);
}

/* SIGUSR1 handler. */
void
sigusr1 (int sig)
{
  zlog_rotate (NULL);
}

/* Signale wrapper. */
RETSIGTYPE *
signal_set (int signo, void (*func)(int))
{
  int ret;
  struct sigaction sig;
  struct sigaction osig;

  sig.sa_handler = func;
  sigemptyset (&sig.sa_mask);
  sig.sa_flags = 0;
#ifdef SA_RESTART
  sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

  ret = sigaction (signo, &sig, &osig);

  if (ret < 0) 
    return (SIG_ERR);
  else
    return (osig.sa_handler);
}

/* Initialization of signal handles. */
void
signal_init ()
{
  signal_set (SIGHUP, sighup);
  signal_set (SIGINT, sigint);
  signal_set (SIGTERM, sigint);
  signal_set (SIGPIPE, SIG_IGN);
  signal_set (SIGUSR1, sigusr1);
}

/* Main startup routine. */
int
main (int argc, char **argv)
{
  char *p;
  int vty_port = 0;
  char *vty_addr = NULL;
  int daemon_mode = 0;
  char *config_file = NULL;
  char *progname;
  struct thread thread;
  int test=1;//testing
  /* Set umask before anything for security */
  umask (0027);

  /* preserve my name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  zlog_default = openzlog (progname, ZLOG_STDOUT, ZLOG_LDP,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  while (1) 
    {
      int opt;
  
      opt = getopt_long (argc, argv, "bdklf:hP:rv", longopts, 0);

      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'l':
	  /* log_mode = 1; */
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
	}
    }

  /* Make master thread emulator. */
  master = thread_master_create();

  /* Vty related initialize. */
  signal_init();
  cmd_init(1);
  vty_init(master);
  memory_init();

  /* LDP inits */
  ldp_init();
  ldp_interface_init();
  ldp_vty_init();
  ldp_vty_show_init();
  ldp_zebra_init();

  sort_node();
 
  vty_read_config(config_file, config_default);

  /* Daemonize. */
  if (daemon_mode) {
    daemon(0, 0);
  }

  /* Output pid of zebra. */
  pid_output(pid_file);

  /* Create VTY socket */
  vty_serv_sock(vty_addr,
		vty_port ? vty_port : LDP_VTY_PORT, LDP_VTYSH_PATH);

#ifdef DEBUG
  /* Print banner. */
  zlog (NULL, LOG_INFO, "LDPd (%s) starts", QUAGGA_VERSION);
#endif


  while(thread_fetch(master, &thread)) thread_call(&thread);

  /* Not reached... */
  exit (0);
}

