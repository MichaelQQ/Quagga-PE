
/*
 *  Copyright (C) James R. Leu 2002
 *  jleu@mindspring.com
 *
 *  This software is covered under the LGPL, for more
 *  info check out http://www.gnu.org/copyleft/lgpl.html
 */

#ifndef _MPLS_LIST_H_
#define _MPLS_LIST_H_

#include "mpls_mm_impl.h"

/* Endo list, the prev,next ptrs are part of the element in the list */
/* No addition memory allocations are done when inserting into the list */

#define MPLS_LIST_ROOT(name,type)	\
struct name {				\
  struct type *llh_first;		\
  struct type *llh_last;		\
  int count;				\
}

#define MPLS_LIST_ELEM(type)		\
struct {				\
  struct type *lle_next;		\
  struct type *lle_prev;		\
}

#define MPLS_LIST_REMOVE(head, elm, field) {				\
  if((elm)->field.lle_next == (void *)(head))				\
    (head)->llh_last = (elm)->field.lle_prev;				\
  else									\
    (elm)->field.lle_next->field.lle_prev = (elm)->field.lle_prev;	\
  if((elm)->field.lle_prev == (void *)(head))				\
    (head)->llh_first = (elm)->field.lle_next;				\
  else									\
    (elm)->field.lle_prev->field.lle_next = (elm)->field.lle_next;	\
 (head)->count--;						}

#define MPLS_LIST_INSERT_BEFORE(head,listelm,elm,field) {	\
  (elm)->field.lle_next = (listelm);				\
  (elm)->field.lle_prev = (listelm)->field.lle_prev;		\
  if((listelm)->field.lle_prev == (void *)(head))		\
    (head)->llh_first = (elm);					\
  else								\
    (listelm)->field.lle_prev->field.lle_next = (elm);		\
  (listelm)->field.lle_prev = (elm);				\
  (head)->count++;						\
}

#define MPLS_LIST_INIT(head,type) {		\
  (head)->llh_first = (struct type *)(head);	\
  (head)->llh_last = (struct type *)(head);	\
  (head)->count = 0;				\
}

#define MPLS_LIST_IN_LIST(elm,field) ((elm)->field.lle_next && (elm)->field.lle_prev)

#define MPLS_LIST_ADD_HEAD(head, elm, field, type) {	\
  (elm)->field.lle_next = (head)->llh_first;		\
  (elm)->field.lle_prev = (struct type *)(head);	\
  if ((head)->llh_last == (struct type *)(head))	\
    (head)->llh_last = (elm);				\
  else							\
    (head)->llh_first->field.lle_prev = (elm);		\
  (head)->llh_first = (elm);				\
  (head)->count++;					\
}

#define MPLS_LIST_ADD_TAIL(head, elm, field, type) {	\
  (elm)->field.lle_next = (struct type *)(head);	\
  (elm)->field.lle_prev = (head)->llh_last;		\
  if ((head)->llh_first == (struct type *)(head))	\
    (head)->llh_first = (elm);				\
  else							\
    (head)->llh_last->field.lle_next = (elm);		\
  (head)->llh_last = (elm);				\
  (head)->count++;					\
}

#define MPLS_LIST_REMOVE_TAIL(root,elem,field) {	\
  (elem) = (root)->llh_last;			\
  if((elem) && (elem) != (void*)(root)) {	\
    MPLS_LIST_REMOVE(root,elem,field);		\
  } else {					\
    (elem) = NULL;				\
  }						\
  (root)->count--;				\
}

#define MPLS_LIST_REMOVE_HEAD(root,elem,field) {	\
  (elem) = (root)->llh_first;			\
  if((elem) && (elem) != (void*)(root)) {	\
    MPLS_LIST_REMOVE(root,elem,field);		\
  } else {					\
    (elem) = NULL;				\
  }						\
  (root)->count--;				\
}

#define MPLS_LIST_ELEM_INIT(elem,field) {	\
  (elem)->field.lle_next = NULL;		\
  (elem)->field.lle_prev = NULL;		\
}

#define MPLS_LIST_HEAD(root)		(((root)->llh_first == (void*)(root))?(NULL):((root)->llh_first))
#define MPLS_LIST_NEXT(root,elem,field)	((((elem)->field.lle_next) == (void*)(root))?(NULL):((elem)->field.lle_next))
#define MPLS_LIST_PREV(root,elem,field)	((((elem)->field.lle_prev) == (void*)(root))?(NULL):((elem)->field.lle_prev))
#define MPLS_LIST_TAIL(root)		(((root)->llh_last == (void*)(root))?(NULL):((root)->llh_last))

#define MPLS_LIST_EMPTY(root) ((root)->count ? MPLS_BOOL_FALSE : MPLS_BOOL_TRUE)

/* non Endo list, the list node has the next,prev pointers and a pointer to */
/* the data being stored, a memory allocation has to occur for each insert */

typedef struct mpls_link_list_node {
  struct mpls_link_list_node *next;
  struct mpls_link_list_node *prev;
  void *data;
} mpls_link_list_node;

typedef struct mpls_link_list {
  struct mpls_link_list_node *head;
  struct mpls_link_list_node *tail;
  int count;
} mpls_link_list;

#define mpls_link_list_head(X) ((X)->head)
#define mpls_link_list_head_data(X) ((X)->head ? (X)->head->data : NULL)
#define mpls_link_list_tail(X) ((X)->tail)
#define mpls_link_list_tail_data(X) ((X)->tail ? (X)->tail->data : NULL)
#define mpls_link_list_count(X) ((X)->count)
#define mpls_link_list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)

#define MPLS_LINK_LIST_LOOP(LIST,DATA,NODE)			\
  for ((NODE) = (LIST)->head; (NODE); (NODE) = (NODE)->next)	\
    if (((DATA) = (NODE)->data) != NULL)

static inline void mpls_link_list_init(struct mpls_link_list *list) {
  memset(list, 0, sizeof(*list));
}

static inline struct mpls_link_list *mpls_link_list_create() {
  struct mpls_link_list *list;

  if ((list = mpls_malloc(sizeof(*list)))) {
    mpls_link_list_init(list);
  }
  return list;
}

static inline void mpls_link_list_delete(struct mpls_link_list *list) {
  mpls_free(list);
}

static inline struct mpls_link_list_node *mpls_link_list_node_create(void *data)
{
  struct mpls_link_list_node *node;

  if ((node = mpls_malloc(sizeof(*node)))) {
    memset(node, 0, sizeof(*node));
    node->data = data;
  }
  return node;
}

static inline void mpls_link_list_node_delete(struct mpls_link_list_node *node)
{
  mpls_free(node);
}

static inline void mpls_link_list_add_node_head(struct mpls_link_list *list,
  struct mpls_link_list_node *node) {
  node->next = list->head;
    
  if (list->tail == NULL) {
    list->tail = node; 
  } else {
    list->head->prev = node;
    node->next = list->head;
  }
  list->head = node;
  list->count++;
}

static inline mpls_return_enum mpls_link_list_add_head(
  struct mpls_link_list *list, void * data) {
  struct mpls_link_list_node *node;

  if ((node = mpls_link_list_node_create(data))) {
    mpls_link_list_add_node_head(list,node);
    return MPLS_SUCCESS;
  }
  return MPLS_FATAL;
}

static inline void mpls_link_list_add_node_tail(
  struct mpls_link_list *list, struct mpls_link_list_node *node) {
  node->prev = list->tail;

  if (list->head == NULL) {
    list->head = node; 
  } else {
    node->prev = list->tail;
    list->tail->next = node;
  }
  list->tail = node;
  list->count++;
}

static inline mpls_return_enum mpls_link_list_add_tail(
  struct mpls_link_list *list, void *data) {
  struct mpls_link_list_node *node;

  if ((node = mpls_link_list_node_create(data))) {
    mpls_link_list_add_node_tail(list, node);
    return MPLS_SUCCESS;
  }
  return MPLS_FATAL;
}

static inline void mpls_link_list_add_node_before(struct mpls_link_list *list,
  struct mpls_link_list_node *ptr, struct mpls_link_list_node *node) {
  if (list->head == ptr) {
    node->next = ptr;
    ptr->prev = node;
    list->head = node;
  } else {
    node->prev = ptr->prev;
    node->next = ptr;
    ptr->prev->next = node;
    ptr->prev = node;
  }
  list->count++;
}

static inline mpls_return_enum mpls_link_list_add_data_before(
  struct mpls_link_list *list, struct mpls_link_list_node *ptr, void *data) {
  struct mpls_link_list_node *node;

  if ((node = mpls_link_list_node_create(data))) {
    mpls_link_list_add_node_before(list,ptr,node);
    return MPLS_SUCCESS;
  }
  return MPLS_FATAL;
}

static inline void mpls_link_list_add_node_after(struct mpls_link_list *list,
  struct mpls_link_list_node *ptr, struct mpls_link_list_node *node) {
  if (list->tail == ptr) {
    ptr->next = node;
    node->prev = ptr; 
    list->tail = node;
  } else {
    node->prev = ptr;
    node->next = ptr->next;
    ptr->next = node;
    ptr->next->prev = node;
  }
  list->count++;
}

static inline mpls_return_enum mpls_link_list_add_data_after(
  struct mpls_link_list *list, struct mpls_link_list_node *ptr, void *data) {
  struct mpls_link_list_node *node;

  if ((node = mpls_link_list_node_create(data))) {
    mpls_link_list_add_node_after(list, ptr, node);
    return MPLS_SUCCESS;
  }
  return MPLS_FATAL;
}

static inline void mpls_link_list_remove_node(struct mpls_link_list *list,
  struct mpls_link_list_node *node) {

  if (node->prev) {
    node->prev->next = node->next;
  } else {
    list->head = node->next;
  }

  if (node->next) {
    node->next->prev = node->prev;
  } else {
    list->tail = node->prev;
  }

  list->count--;
}

static inline void mpls_link_list_remove_data(struct mpls_link_list* list,
  void *val)
{
  struct mpls_link_list_node *node;

  for (node = list->head; node; node = node->next) {
    if (node->data == val) {
      mpls_link_list_remove_node(list,node);
      mpls_link_list_node_delete(node);
      break;
    }
  }
}

#endif
