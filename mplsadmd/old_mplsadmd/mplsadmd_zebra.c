#include "zebra.h"
#include "command.h"
#include "log.h"

#include "zclient.h"
struct zclient *zclient = NULL;

/* Zebra route add and delete treatment. */
int mplsadmd_zebra_read_ipv4 (int command, struct zclient *zclient, zebra_size_t length)
{
  if (command == ZEBRA_IPV4_ROUTE_ADD)
    zlog_info ("ADD");
  else 
    zlog_info ("DEL");
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{ ZEBRA_NODE, "%s(config-router)# ", };

/* MPLSADMD configuration write function. */
int config_write_zebra (struct vty *vty)
{
  if (! zclient->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

DEFUN (
	router_zebra,
	router_zebra_cmd,
	"router zebra",

	"Enable a routing process\n"
	"Make connection to zebra daemon\n")
{
  vty->node = ZEBRA_NODE;
  zclient->enable = 1;
  zclient_start (zclient);
  return CMD_SUCCESS;
}

DEFUN (
	no_router_zebra,
	no_router_zebra_cmd,
	"no router zebra",
	NO_STR
	"Enable a routing process\n"
	"Make connection to zebra daemon\n")
{

  zclient->enable = 0;
  zclient_stop (zclient);
  return CMD_SUCCESS;
}

void mplsadmd_zclient_init(void)
{
  /* Set default value to the zebra client structure. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_MPLSADMD);

  zclient->ipv4_route_add = mplsadmd_zebra_read_ipv4;
  zclient->ipv4_route_delete = mplsadmd_zebra_read_ipv4;

  /* Install zebra node. */
  install_node (&zebra_node, config_write_zebra);

  /* Install command elements to zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);
  install_default (ZEBRA_NODE);
}

