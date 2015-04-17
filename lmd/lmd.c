#include <stdio.h>
#include "lmd.h"
struct LM_LabelPool *lm_head = NULL;
/* LMD instance top. */
struct LM_LabelPool *LM_LabelPool_new(void) {

	struct LM_LabelPool *new;
	new=(struct LM_LabelPool *)malloc(sizeof(struct LM_LabelPool));
	
	if(!new)
		return	NULL;//memory allocate fail
	
	//initial 
	memset(new,0,sizeof(*new));
	lm_head=new;
	return new;
}

struct LM_LabelPool *LM_LabelPool_new_more(struct LM_LabelPool *pool) {
	
	struct LM_LabelPool *new;
	new=(struct LM_LabelPool *)malloc(sizeof(struct LM_LabelPool));
	
	if(!new)
		return	NULL;//memory allocate fail
	
	//initial 
	memset(new,0,sizeof(*new));
	new->next=pool;
	pool=new;
  lm_head=new;
	return new;
}

struct LM_LabelPool *lm_get(){
    if (lm_head){
			return lm_head;
    }
    return NULL;
}