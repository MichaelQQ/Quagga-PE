#ifndef LMD_H
#define LMD_H


/*--------------------------------------------------------------------------------------*/
#if 0
#define DEBUGP printf
#else
#define DEBUGP(format, args...)
#endif
/*--------------------------------------------------------------------------------------*/

struct LM_Message
 {
  //LM_Command command;
  int number;
  int parameter[5]; 
 }LM_Message;

struct LM_Element
 {
  int min, max;
  struct LM_Element *left, *right;
 };

struct LM_LabelPool
 {
  int pool_id;
  unsigned long min,max;
  struct LM_LabelPool *next; 
  struct LM_Element *root;  
 };
// struct LM_LabelPool *lm_head;
// tunnel_entry *tunnel_new(void);
//create a new lm instance function code
struct LM_LabelPool *LM_LabelPool_new();
struct LM_LabelPool *LM_LabelPool_new_more(struct LM_LabelPool *pool); 
struct LM_LabelPool *lm_get();


#endif


/*
int lm_init(int);
int lm_close(int);
int CreateLabelPool(int, int, int);
int RequestLabelFromPool(int);
int ReleaseLabelToPool(int, int);

#define LM_CLI_NUM 4		//LDP, RSVP-TE, MAIN
enum
 {
  LM_INIT_MAIN,
  LM_INIT_LDP,
  LM_INIT_RSVP_TE,
  LM_INIT_VPN_MANAGER
 };

static char LM_PATH[LM_CLI_NUM][2][32]={
    {"/tmp/lm_main","/tmp/lm_main1"},
    {"/tmp/lm_ldp","/tmp/lm_ldp1"},
    {"/tmp/lm_rsvp","/tmp/lm_rsvp1"},
    {"/tmp/lm_vpn_manager","/tmp/lm_vpn_manager1"}
};

typedef enum 
 {
  lmCreateLabelPool,
  lmDeleteLabelPool,
  lmCheckLabelPool,
  lmRequestLabelFromPool,
  lmReleaseLabelToPool,
  lmCheckLabelInPool,
  lmCheckLabelRangeInPool,
  lmRequestSpecifiedLabelFromPool,
  lmReturnValue
 }LM_Command;
*/

