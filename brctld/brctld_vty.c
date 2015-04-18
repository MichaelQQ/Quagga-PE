#include "zebra.h"
#include "command.h"
#include "log.h"

#include "libbrctl.h"

DEFUN(router_brctld,
	router_brctld_cmd,
	"router brctld",
	"Enable a routing process "
	"BRCTLD process")
{
 vty->node = BRCTLD_NODE;
 vty_out (vty, "Down to brctld node%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  version_brctld,
        version_brctld_cmd,
        "version",
        "show bridge version "
        "bridge control user space tool")
{
 vty_out(vty,"version 1%s",VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  addbr_brctld,
        addbr_brctld_cmd,
        "add bridge WORD",
        "add new virtual bridge device "
        "bridge control user space tool")
{
 int retval=-1;
 retval=addbr_cmd(argv[0]);
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  delbr_brctld,
        delbr_brctld_cmd,
        "del bridge WORD",
        "delete the virtual bridge device "
        "bridge control user space tool")
{
 int retval=-1;
 retval=delbr_cmd(argv[0]);
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  addif_brctld,
        addif_brctld_cmd,
        "addif bridge WORD if WORD",
        "add the interface for virtual bridge device "
        "bridge control user space tool")
{
 int retval=-1;
 retval=addif_cmd(argv[0],argv[1]);
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 return CMD_SUCCESS;
}


DEFUN(  delif_brctld,
        delif_brctld_cmd,
        "delif bridge WORD if WORD",
        "delete the interface for virtual bridge device "
        "bridge control user space tool")
{
 int retval=-1;
 retval=delif_cmd(argv[0],argv[1]);
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  setageing_brctld,
        setageing_brctld_cmd,
        "setageing  bridge WORD timer <0-100>",
        "set bridge ageing timer "
        "bridge control user space tool")
{
 int retval=-1;
 retval=setageing_cmd(argv[0],atoi(argv[1]));
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 return CMD_SUCCESS;
}
DEFUN(  stp_brctld,
        stp_brctld_cmd,
        "set stp bridge WORD on/off WORD",
        "set bridge stp on/off "
        "bridge control user space tool")
{
 int retval=-1;
 retval=stp_cmd(argv[0],argv[1]);
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  show_brctld,
        show_brctld_cmd,
        "show stauts ",
        "show all bridge status  "
        "bridge control user space tool")
{
 int retval=-1;
 retval=show_cmd();
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 return CMD_SUCCESS;
}
DEFUN(  showmacs_brctld,
        showmacs_brctld_cmd,
        "show macs bridge WORD",
        "show macs table of virtual bridge device "
        "bridge control user space tool")
{
 int retval=-1;
 retval=showmacs_cmd(argv[0]);
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 return CMD_SUCCESS;
}
DEFUN(  showstp_brctld,
        showstp_brctld_cmd,
        "show stp bridge WORD",
        "show bridge stp status "
        "bridge control user space tool")
{
 int retval=-1;
 retval=showstp_cmd(argv[0]);
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 return CMD_SUCCESS;
}


static struct cmd_node brctld_node =
{ BRCTLD_NODE, "%s(config-brctld)# ", 1 };

void brctld_init(void)
{
  install_node( &brctld_node, NULL );
  install_default( BRCTLD_NODE );
	
  install_element( VIEW_NODE, &show_brctld_cmd);
  install_element( ENABLE_NODE, &show_brctld_cmd);
  
  install_element( VIEW_NODE, &showmacs_brctld_cmd);
  install_element( ENABLE_NODE, &showmacs_brctld_cmd);
  
  install_element( VIEW_NODE, &showstp_brctld_cmd);
  install_element( ENABLE_NODE, &showstp_brctld_cmd);
	
  install_element( CONFIG_NODE, &router_brctld_cmd);
  install_element( BRCTLD_NODE, &version_brctld_cmd);
  install_element( BRCTLD_NODE, &addbr_brctld_cmd);
  install_element( BRCTLD_NODE, &delbr_brctld_cmd);
  install_element( BRCTLD_NODE, &addif_brctld_cmd);
  install_element( BRCTLD_NODE, &delif_brctld_cmd);
  
  install_element( BRCTLD_NODE, &setageing_brctld_cmd);
  install_element( BRCTLD_NODE, &stp_brctld_cmd);
}
