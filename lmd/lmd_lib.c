#include <stdio.h>
#include "lmd.h"
#include "lmd_lib.h"


int CreateLabelPool(struct LM_LabelPool *lm_head,int pool_id, int min, int max){
	 	printf("start create label pool_id %d\n",pool_id);
	 	struct LM_LabelPool *ptr;
    struct LM_Element *root_ptr;
    
    ptr=lm_head;
    if(!ptr)
    	ptr=LM_LabelPool_new();
    else
    	ptr=LM_LabelPool_new_more(ptr);

 		/*
    ptr=lm_head;
		
    while(ptr!=NULL && ptr->next!=NULL) ptr=ptr->next;
    if(ptr==NULL)
    {		printf("One lable pool .\n");
        lm_head=ptr=LM_LabelPool_new();//(struct LM_LabelPool *)malloc(sizeof(struct LM_LabelPool));
        if(ptr==NULL) return -1;
    }
    else
    {		printf("More lable pool .\n");
        ptr->next=LM_LabelPool_new();//(struct LM_LabelPool *)malloc(sizeof(struct LM_LabelPool));
        if(ptr->next==NULL) return -1;
        ptr=ptr->next;
    }*/
    //initial
    DEBUGP("initial\n");
    //ptr->next=NULL; Marked by here
    ptr->pool_id=pool_id;
    DEBUGP("initial pool id %d\n",ptr->pool_id);
    ptr->min=min;
    ptr->max=max;
    ptr->root=(struct LM_Element *)malloc(sizeof(struct LM_Element));
    if(ptr->root == NULL) 
    {
        free(ptr);
        DEBUGP("alloc element\n");
        return -1;
    }
    root_ptr=ptr->root;
    root_ptr->min=min;
    root_ptr->max=max;
    root_ptr->left=NULL;
    root_ptr->right=NULL;
    DEBUGP("pool id = %d \n",pool_id);
    return pool_id;
	/*
	printf("pool_id :%d\t min :%d\t max:%d\n",pool_id,min,max);
	return pool_id;*/
}

int DeleteLabelPool(struct LM_LabelPool *lm_head,int pool_id){
	  printf("start delete label pool_id %d\n",pool_id);
	  if(!lm_head){
	  	return -1;
	  }
	  struct LM_LabelPool *ptr;
    ptr=lm_head;
    while(ptr!=NULL && ptr->pool_id != pool_id)
        ptr=ptr->next;
    if(ptr==NULL)
        return -1;
    FreeElementTree(ptr->root); 
    free(ptr);
    return 1;
}
//CheckLabelPool not ready for use .
int CheckLabelPool(struct LM_LabelPool *lm_head,int pool_id, int *min, int *max){
	  if(!lm_head){
	  	return -1;
	  }
	  struct LM_LabelPool *ptr;

    ptr=lm_head;

    while(ptr!=NULL && ptr->pool_id != pool_id)
        ptr=ptr->next;
    if(ptr==NULL)
        return -1;
    *min=ptr->min;
    *max=ptr->max;
    return 1;
	//return pool_id;
}

int RequestLabelFromPool(struct LM_LabelPool *lm_head,int pool_id){
		printf("request label form label pool_id %d\n",pool_id);
		if(!lm_head)
	  	return -1;
	 
		struct LM_LabelPool *ptr;
    struct LM_Element *element_ptr, *eptr, *eptr1;
    int label;

    ptr=lm_head;

    DEBUGP("lm : Request label %d!!\n",pool_id);
    while(ptr!=NULL && ptr->pool_id != pool_id)
    {
        DEBUGP("lm : label pool %d %d!!\n",ptr->pool_id,pool_id);
        //printf("lm : label pool %d %d!!\n",ptr->pool_id,pool_id);
        ptr=ptr->next;
    }
    if(ptr==NULL){//printf("ptr==null\n");
        return -1;
		}
    DEBUGP("lm : Request label .. find label pool!!\n");
    if ((element_ptr=ptr->root) == NULL)
        return -1;
    if(element_ptr->max - element_ptr->min) //root node has more than one label
    {
        label=element_ptr->min++;
        return label;
    }
    else
    {
        label=element_ptr->min;		//the latest label in root node

        if(element_ptr->left != NULL)	//search left tree
        {
            eptr=element_ptr->left;
            eptr1=NULL; 
            while(eptr->right !=NULL)		//find the most right element
            {
                eptr1=eptr;			//record the parent 
                eptr=eptr->right; 
            }
            if(eptr1!=NULL) {
                eptr1->right=NULL;
                eptr->left=element_ptr->left;
                eptr->right=element_ptr->right;
            }
            else                                //the final element
                eptr->right=element_ptr->right;
            ptr->root=eptr;
        }
        else if(element_ptr->right != NULL)	//search right tree
        {
            eptr=element_ptr->right;
            eptr1=NULL; 
            while(eptr->left !=NULL)		//find the most left element
            {
                eptr1=eptr;			//record the parent 
                eptr=eptr->left; 
            }
            if(eptr1!=NULL) {
                eptr1->left=NULL;
                eptr->left=element_ptr->left;
                eptr->right=element_ptr->right;
            }
            else                                //the final element
                eptr->left=element_ptr->left;
            ptr->root=eptr;
        }
        else
            ptr->root=NULL;
        free(element_ptr);
        return label;
    }
    return -1;
}
int RequestSpecifiedLabelFromPool(struct LM_LabelPool *lm_head,int pool_id, int label){
    printf("request specified label form label pool_id %d\n",pool_id);
    if(!lm_head){
	  	return -1;
	  }
    struct LM_LabelPool *ptr;
    struct LM_Element *element_ptr, *eptr;

    ptr=lm_head;

    while(ptr!=NULL && ptr->pool_id != pool_id)
        ptr=ptr->next;
    if(ptr==NULL)
        return -1;

    element_ptr=ptr->root;
    //search the tree
    while(element_ptr!=NULL)
    {
        if(label>=element_ptr->min && label <= element_ptr->max)	//this node
        {
            if(label == element_ptr->min)
            {
                element_ptr->min++;
                return 1;	//OK
            }
            else if(label == element_ptr->max)
            {
                element_ptr->max--;
                return 1;	//OK
            }
            else
            {
                //create a new node
                eptr=(struct LM_Element *)malloc(sizeof(struct LM_Element));
                if(eptr == NULL)
                {
                    return -1; 	//memory is not enough
                }
                eptr->left=element_ptr->left;
                eptr->right=NULL;
                eptr->min=element_ptr->min;
                eptr->max=label-1;

                element_ptr->min=label+1;
                element_ptr->left=eptr;

                return 1; 	// OK

            }

        }
        else if(label<element_ptr->min)
        {
            if(element_ptr->left == NULL)	//most left node
                return -1; //label not exist
            element_ptr=element_ptr->left;
        }
        else if(label>element_ptr->max)
        {
            if(element_ptr->right == NULL)	//most right node
                return -1; //label not exist
            element_ptr=element_ptr->right;
        }
        else
            return -1;//ERROR!!
    }

    return 1;
}

int ReleaseLabelToPool(struct LM_LabelPool *lm_head,int pool_id, int label){
		printf("release label %d to pool_id %d\n",label,pool_id);
		if(!lm_head){
	  	return -1;
	  }
    struct LM_LabelPool *ptr;
    struct LM_Element *element_ptr, *eptr;

    ptr=lm_head;

    while(ptr!=NULL && ptr->pool_id != pool_id)
        ptr=ptr->next;
    if(ptr==NULL)
        return -1;

    if(ptr->root==NULL) {
        ptr->root = (struct LM_Element *)malloc(sizeof(struct LM_Element));
        ptr->root->max = ptr->root->min = label;
        ptr->root->right = ptr->root->left = NULL;
        return 1;
    }

    element_ptr=ptr->root;
    //search the tree
    while(element_ptr!=NULL)
    {
        if(label==element_ptr->min-1)
        {
            element_ptr->min=label;
            return 1;	//OK
        }
        else if(label==element_ptr->max+1)
        {
            element_ptr->max=label;
            return 1;	//OK
        }
        else if(label>element_ptr->max)
        {
            if(element_ptr->right == NULL)	//most right node
            {
                //create a new node
                eptr=(struct LM_Element *)malloc(sizeof(struct LM_Element));
                if(eptr == NULL)
                {
                    return -1; 	//memory is not enough
                }
                element_ptr->right=eptr;
                eptr->left=NULL;
                eptr->right=NULL;
                eptr->min=label;
                eptr->max=label;

                return 1; 	// OK
            }
            else
            {
                //find next right node
                element_ptr=element_ptr->right;
                continue;
            }
        }
        else if(label<element_ptr->min)
        {
            if(element_ptr->left == NULL)	//most left node
            {
                //create a new node
                eptr=(struct LM_Element *)malloc(sizeof(struct LM_Element));
                if(eptr == NULL)
                {
                    return -1; 	//memory is not enough
                }
                element_ptr->left=eptr;
                eptr->left=NULL;
                eptr->right=NULL;
                eptr->min=label;
                eptr->max=label;

                return 1; 	// OK
            }
            else
            {
                //find next left node
                element_ptr=element_ptr->left;
                continue;
            }
        }
        else
            return -1;//ERROR!!
    }

    return 1;
}

int CheckLabelInPool(struct LM_LabelPool *lm_head,int pool_id, int label){
	  printf("check label %d in label pool_id %d\n",label,pool_id);
	  if(!lm_head){
	  	return -1;
	  }
	  struct LM_LabelPool *ptr;

    ptr=lm_head;

    while(ptr!=NULL && ptr->pool_id != pool_id)
        ptr=ptr->next;
    if(ptr==NULL)
        return -1;

    if(label>=ptr->min && label<=ptr->max)
        return 1;
    else
        return 0;
//return pool_id;
}

int CheckLabelRangeInPool(struct LM_LabelPool *lm_head,int pool_id, int min, int max){
   	printf("check label range min %d to max %d in label pool_id %d\n",min,max,pool_id);
    if(!lm_head){
	  	return -1;
	  }
    struct LM_LabelPool *ptr;

    ptr=lm_head;

    while(ptr!=NULL && ptr->pool_id != pool_id)
        ptr=ptr->next;
    if(ptr==NULL)
        return -1;

    if(min>=ptr->min && min<=ptr->max &&
            max>=ptr->min && max<=ptr->max )
        return 1;
    else
        return 0;
//return pool_id;
}

int  in_use_poolid(struct LM_LabelPool *lm_head){
	if(!lm_head){
			printf("No pool_id\n");
			return -1;
	}
	do{
			printf("pool_id:%d\n",lm_head->pool_id);
		}while(lm_head->next!=NULL);
		return 0;
}


/*----------------------------------------------------------------------------*/
void FreeElementTree(struct LM_Element *ptr)
{
    if(ptr->left != NULL)
    {
        FreeElementTree(ptr->left);
        ptr->left=NULL;
    }
    if(ptr->right != NULL)
    {
        FreeElementTree(ptr->right);
        ptr->right=NULL;
    }
    free(ptr);
}
/*----------------------------------------------------------------------------*/