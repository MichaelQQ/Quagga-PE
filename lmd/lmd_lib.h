#ifndef LMD_LIB_H
#define LMD_LIB_H
int CreateLabelPool(struct LM_LabelPool *lm_head,int pool_id, int min, int max);
int DeleteLabelPool(struct LM_LabelPool *lm_head,int pool_id);
int CheckLabelPool(struct LM_LabelPool *lm_head,int pool_id, int *min, int *max);
int RequestLabelFromPool(struct LM_LabelPool *lm_head,int pool_id);
int RequestSpecifiedLabelFromPool(struct LM_LabelPool *lm_head,int pool_id, int label);
int ReleaseLabelToPool(struct LM_LabelPool *lm_head,int pool_id, int label);
int CheckLabelInPool(struct LM_LabelPool *lm_head,int pool_id, int label);
int CheckLabelRangeInPool(struct LM_LabelPool *lm_head,int pool_id, int min, int max);

int in_use_poolid(struct LM_LabelPool *lm_head);
void FreeElementTree(struct LM_Element *ptr);
/*
int lm_init(int i);
int lm_close(int i);
*/
#endif

