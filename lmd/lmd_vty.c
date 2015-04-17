#include "zebra.h"
#include "command.h"
#include "log.h"

DEFUN(router_lmd,
	router_lmd_cmd,
	"router lmd",
	"Enable a routing process"
	"LMD protocol")
{
 vty->node = LMD_NODE;
// vty_out (vty, "Down to lmd node%s", VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  createLabelPool_lmd,
        createLabelPool_lmd_cmd,
        "createLabelPool pool_id <1-100> min_label <1-10000> max_label <1-100000>",
        "create a new Label Pool for use"
        "LMD protocol")
{
 //vty->node = LMD_NODE;
 //vty_out(vty,"Test message%s", VTY_NEWLINE);
 struct LM_LabelPool *lm=lm_get();
 int retval=CreateLabelPool(lm,atoi(argv[0]),atoi(argv[1]),atoi(argv[2]));
 //printf("retval :%d\n",retval);
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 //CreateLabelPool(lm,atoi(argv[0]),atoi(argv[1]),atoi(argv[2]));
 return CMD_SUCCESS;
 /*
 struct LM_LabelPool *lm=lm_get();
 if(!lm)
 		return CMD_WARNING;
 int retval=CreateLabelPool(lm,atoi(argv[0]),atoi(argv[1]),atoi(argv[2]));*/
}

DEFUN(  deleteLabelPool_lmd,
        deleteLabelPool_lmd_cmd,
        "deleteLabelPool pool_id <1-100>",
        "delete the label pool by pool_id"
        "LMD protocol")
{
 vty->node = LMD_NODE;
 struct LM_LabelPool *lm=lm_get();
 int retval=DeleteLabelPool(lm,atoi(argv[0]));
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 /*
 if(DeleteLabelPool(lm,atoi(argv[0]))< 0){
 		vty_out(vty,"DeleteLabelPool fail.%s",VTY_NEWLINE);
 		return CMD_WARNING;
 }
 vty_out(vty,"deleteLabelPool pool_id %d %s",atoi(argv[0]),VTY_NEWLINE);
 */
 return CMD_SUCCESS;
}

//checkLabelPool_lmd_cmd not ready for use

DEFUN(  checkLabelPool_lmd,
        checkLabelPool_lmd_cmd,
        "checkLabelPool pool_id <1-100> min_label <1-100> max_label <1-10000>",
        "check the label pool by pool_id"
        "LMD protocol")
{
 vty->node = LMD_NODE;
 struct LM_LabelPool *lm=lm_get();
 int *min,*max; //need to refix min and max value to check this function.
 if(CheckLabelPool(lm,atoi(argv[0]),min,max)< 0){
 		vty_out(vty,"checkLabelPool fail.%s",VTY_NEWLINE);
 		return CMD_WARNING;
 }
 vty_out(vty,"checkLabelPool pool_id %d %s",atoi(argv[0]),VTY_NEWLINE);
 return CMD_SUCCESS;
}

DEFUN(  requestLabelFromPool_lmd,
        requestLabelFromPool_lmd_cmd,
        "requestLabelFromPool pool_id <1-100>",
        "request a new Label from Pool_id"
        " LMD daemon")
{
// vty->node = LMD_NODE;
 struct LM_LabelPool *lm=lm_get();
 int retval=RequestLabelFromPool(lm,atoi(argv[0]));
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 
 /*
 if(RequestLabelFromPool(lm,atoi(argv[0])) < 0){
 		vty_out(vty,"RequestLabelFromPool fail.%s",VTY_NEWLINE);
 		return CMD_WARNING;
 }
 vty_out(vty,"requestLabelFromPool pool_id %d %s",atoi(argv[0]),VTY_NEWLINE);
 */
 return CMD_SUCCESS;
}

DEFUN(  requestSpecifiedLabelFromPool_lmd,
        requestSpecifiedLabelFromPool_lmd_cmd,
        "requestSpecifiedLabelFromPool pool_id <1-100> label <1-10000>",
        "request a new Label from Pool_id"
        "LMD protocol")
{
 vty->node = LMD_NODE;
 struct LM_LabelPool *lm=lm_get();
 int retval=RequestSpecifiedLabelFromPool(lm,atoi(argv[0]),atoi(argv[1]));
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 /*
 if(RequestSpecifiedLabelFromPool(lm,atoi(argv[0]),atoi(argv[1])) < 0){
 		vty_out(vty,"RequestLabelFromPool fail.%s",VTY_NEWLINE);
 		return CMD_WARNING;
 } 
 vty_out(vty,"RequestSpecifiedLabelFromPool pool_id %d label :%d %s",atoi(argv[0]),atoi(argv[1]),VTY_NEWLINE);
 */
 return CMD_SUCCESS;
}

DEFUN(  releaseLabelToPool_lmd,
        releaseLabelToPool_lmd_cmd,
        "releaseLabelToPool pool_id <1-100> label <1-10000>",
        "release the Label from Pool_id"
        "LMD protocol")
{
 vty->node = LMD_NODE;
 struct LM_LabelPool *lm=lm_get();
 int retval=ReleaseLabelToPool(lm,atoi(argv[0]),atoi(argv[1]));
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 /*
 if(ReleaseLabelToPool(lm,atoi(argv[0]),atoi(argv[1])) < 0){
 		vty_out(vty,"RequestLabelFromPool fail.%s",VTY_NEWLINE);
 		return CMD_WARNING;
 } 
 vty_out(vty,"ReleaseLabelToPool pool_id %d label :%d %s",atoi(argv[0]),atoi(argv[1]),VTY_NEWLINE);
 */
 return CMD_SUCCESS;
}

DEFUN(  checkLabelInPool_lmd,
        checkLabelInPool_lmd_cmd,
        "checkLabelInPool pool_id <1-100> label <1-10000>",
        "check the Label from Pool_id"
        "LMD protocol")
{
 vty->node = LMD_NODE;
 struct LM_LabelPool *lm=lm_get();
 int retval=CheckLabelInPool(lm,atoi(argv[0]),atoi(argv[1])); 
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 /*
 int retval=CheckLabelInPool(lm,atoi(argv[0]),atoi(argv[1])); 
 //if retval==1 , it mean the lable range isn't the same.
 if(retval < 0){
 		vty_out(vty,"CheckLabelInPool fail.%s",VTY_NEWLINE);
 		return CMD_WARNING;
 }else if(retval > 0){
 		vty_out(vty,"CheckLabelInPool the label range isn't the same.%s",VTY_NEWLINE);
 		return CMD_WARNING;
 }
 // other; retval==0 ;
 //CheckLabelInPool(atoi(argv[0]),atoi(argv[1]));
 vty_out(vty,"CheckLabelInPool pool_id %d label :%d %s",atoi(argv[0]),atoi(argv[1]),VTY_NEWLINE);
 */
 return CMD_SUCCESS;
}

DEFUN(  checkLabelRangeInPool_lmd,
        checkLabelRangeInPool_lmd_cmd,
        "checkLabelRangeInPool pool_id <1-100> min_label <1-100> max_label <1-10000>",
        "check the Label range from Pool_id"
        "LMD protocol")
{
 vty->node = LMD_NODE;
 struct LM_LabelPool *lm=lm_get();
 int retval=CheckLabelRangeInPool(lm,atoi(argv[0]),atoi(argv[1]),atoi(argv[2])); 
 vty_out(vty,"%d%s",retval,VTY_NEWLINE);
 /*
 int retval=CheckLabelRangeInPool(lm,atoi(argv[0]),atoi(argv[1]),atoi(argv[2])); 
 //if retval==1 , it mean the lable range isn't the same.
 if(retval < 0){
 		vty_out(vty,"CheckLabelRangeInPool fail.%s",VTY_NEWLINE);
 		return CMD_WARNING;
 }else if(retval > 0){
 		vty_out(vty,"CheckLabelRangeInPool the label range isn't the same.%s",VTY_NEWLINE);
 		return CMD_WARNING;
 }
 
 //CheckLabelRangeInPool(atoi(argv[0]),atoi(argv[1]),atoi(argv[2]));
 vty_out(vty,"CheckLabelRangeInPool pool_id %d min :%d  max :%d %s",atoi(argv[0]),atoi(argv[1]),atoi(argv[2]),VTY_NEWLINE);
 */
 return CMD_SUCCESS;
}
//end by here
/*
//test install_element node location
//view node 
DEFUN(  view_node_lmd,
        view_node_lmd_cmd,
        "view_node ",
        "view_node "
        "LMD protocol")
{
 vty->node = LMD_NODE;
 //CheckLabelRangeInPool(atoi(argv[0]),atoi(argv[1]),atoi(argv[2]));
 vty_out(vty,"locat at view_node %s",VTY_NEWLINE);
 return CMD_SUCCESS;
}
//ENABLE node 
DEFUN(  enable_node_lmd,
        enable_node_lmd_cmd,
        "enable_node ",
        "enable_node "
        "LMD protocol")
{
 vty->node = LMD_NODE;
 //CheckLabelRangeInPool(atoi(argv[0]),atoi(argv[1]),atoi(argv[2]));
 vty_out(vty,"locat at enable_node %s",VTY_NEWLINE);
 return CMD_SUCCESS;
}
//CONFIG node 
DEFUN(  config_node_lmd,
        config_node_lmd_cmd,
        "config_node ",
        "config_node "
        "LMD protocol")
{
 vty->node = LMD_NODE;
 //CheckLabelRangeInPool(atoi(argv[0]),atoi(argv[1]),atoi(argv[2]));
 vty_out(vty,"locat at config_node %s",VTY_NEWLINE);
 return CMD_SUCCESS;
}
//end test
*/
static struct cmd_node lmd_node =
{ LMD_NODE, "%s(config-lmd)# ", 1 };

void lmd_init(void)
{
install_node( &lmd_node, NULL );
install_default( LMD_NODE );

//install_element (VIEW_NODE,   &router_mplsadmd_cmd);
//install_element (ENABLE_NODE, &router_mplsadmd_cmd);
//install_element (CONFIG_NODE, &router_hered_cmd);
  install_element( CONFIG_NODE, &router_lmd_cmd);
  install_element( LMD_NODE,   &createLabelPool_lmd_cmd);
  install_element( LMD_NODE,   &deleteLabelPool_lmd_cmd);
  //install_element( LMD_NODE,   &checkLabelPool_lmd_cmd);
  install_element( LMD_NODE,   &requestLabelFromPool_lmd_cmd);
  install_element( LMD_NODE,   &requestSpecifiedLabelFromPool_lmd_cmd);
  install_element( LMD_NODE,   &releaseLabelToPool_lmd_cmd);
  install_element( LMD_NODE,   &checkLabelInPool_lmd_cmd);
  install_element( LMD_NODE,   &checkLabelRangeInPool_lmd_cmd);
  /*
  //test install_element node location
  install_element (VIEW_NODE,   &view_node_lmd_cmd);
  install_element (ENABLE_NODE, &enable_node_lmd_cmd);
  install_element (CONFIG_NODE, &config_node_lmd_cmd);
  //end test
	*/
}
