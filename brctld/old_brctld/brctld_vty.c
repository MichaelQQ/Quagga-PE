#include "zebra.h"
#include "command.h"
#include "log.h"

DEFUN(router_brctld,
	router_brctld_cmd,
	"router brctld",
	"Enable a routing process "
	"BRCTLD process")
{
 vty->node = BRCTLD_NODE;
 vty_out (vty, "Down to lmd node%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  createLabelPool_brctld,
        createLabelPool_brctld_cmd,
        "createLabelPool pool_id <1-100> min_label <1-10000> max_label <1-100000>",
        "create a new Label Pool for use"
        "BRCTLD protocol")
{
 //vty->node = BRCTLD_NODE;

 return CMD_SUCCESS;
}
DEFUN(  version_brctld,
        version_brctld_cmd,
        "version",
        "show bridge version "
        "bridge control user space tool")
{
 //vty->node = BRCTLD_NODE;
 vty_out(vty,"version 1%s",VTY_NEWLINE);
 return CMD_SUCCESS;
}

static struct cmd_node brctld_node =
{ BRCTLD_NODE, "%s(config-brctld)# ", 1 };

void brctld_init(void)
{
	install_node( &brctld_node, NULL );
	install_default( BRCTLD_NODE );
  install_element( CONFIG_NODE, &router_brctld_cmd);
  install_element( BRCTLD_NODE, &version_brctld_cmd);
}
