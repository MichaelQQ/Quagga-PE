#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>  //PT for strlen

#include "brctl.h"

#define MAXARGS 25
int arg_index = 0;
char** args;
char buffer[1024]={0};

void alloc_args(void){
  arg_index = 1;
  args = (char**) malloc (MAXARGS*sizeof(char*));
  args[0] = (char*) malloc(sizeof("brctl"));
  sprintf(args[0], "brctl");
}

void free_args(void){
  int i;
  for (i=0; i<arg_index; ++i)
    free(args[i]);
  free(args);
}

void set_arg(const char* argument){
  args[arg_index] = (char*) malloc(sizeof(char)*(strlen(argument)+1));
  sprintf(args[arg_index++], "%s", argument);
}
int addbr_cmd(const char *brname){
	printf("DEBUG(BRCTLD):addbr_cmd enter.\n");
	int res;
  alloc_args();
  set_arg("addbr");
  sprintf(buffer, "%s", brname);
  set_arg(buffer);
  res = brctl_action(arg_index, args);
  free_args();
  printf("DEBUG(BRCTLD):addbr_cmd exit. res:%d.\n",res);
  return res;
}
int delbr_cmd(const char *brname){
	printf("DEBUG(BRCTLD):delbr_cmd enter.\n");
	int res;
  alloc_args();
  set_arg("delbr");
  sprintf(buffer, "%s", brname);
  set_arg(buffer);
  res = brctl_action(arg_index, args);
  free_args();
  printf("DEBUG(BRCTLD):delbr_cmd exit. res:%d.\n",res);
  return res;
}

int addif_cmd(const char* brname,const char*br_if){
	printf("DEBUG(BRCTLD):addif_cmd enter.\n");
	int res;
  alloc_args();
  set_arg("addif");
  sprintf(buffer, "%s", brname);
  set_arg(buffer);
  sprintf(buffer, "%s", br_if);
  set_arg(buffer);
  res = brctl_action(arg_index, args);
  free_args();
  printf("DEBUG(BRCTLD):addif_cmd exit. res:%d.\n",res);
  return res;
}

int delif_cmd(const char* brname,const char*br_if){
	printf("DEBUG(BRCTLD):delif_cmd enter.\n");
	int res;
  alloc_args();
  set_arg("delif");
  sprintf(buffer, "%s", brname);
  set_arg(buffer);
  sprintf(buffer, "%s", br_if);
  set_arg(buffer);
  res = brctl_action(arg_index, args);
  free_args();
  printf("DEBUG(BRCTLD):delif_cmd exit. res:%d.\n",res);
  return res;
}

int setageing_cmd(const char* brname,int timer){
	printf("DEBUG(BRCTLD):setageing_cmd enter.\n");
	int res;
  alloc_args();
  set_arg("setageing");
  sprintf(buffer, "%s", brname);
  set_arg(buffer);
  sprintf(buffer, "%d", timer);
  set_arg(buffer);
  res = brctl_action(arg_index, args);
  free_args();
  printf("DEBUG(BRCTLD):setageing_cmd exit. res:%d.\n",res);
  return res;
}

int stp_cmd(const char* brname,const char*cmd){
	printf("DEBUG(BRCTLD):stp_cmd enter.\n");
	int res;
  alloc_args();
  set_arg("stp");
  sprintf(buffer, "%s", brname);
  set_arg(buffer);
  sprintf(buffer, "%s", cmd);
  set_arg(buffer);
  res = brctl_action(arg_index, args);
  free_args();
  printf("DEBUG(BRCTLD):stp_cmd exit. res:%d.\n",res);
  return res;
}

int show_cmd(){
	int res;
  alloc_args();
  set_arg("show");
  res = brctl_action(arg_index, args);
  free_args();
  return res;
}

int showmacs_cmd(const char* brname){
	int res;
  alloc_args();
  set_arg("showmacs");
  sprintf(buffer, "%s", brname);
  set_arg(buffer);
  res = brctl_action(arg_index, args);
  free_args();
  return res;
}

int showstp_cmd(const char* brname){
	int res;
  alloc_args();
  set_arg("showmacs");
  sprintf(buffer, "%s", brname);
  set_arg(buffer);
  res = brctl_action(arg_index, args);
  free_args();
  return res;
}
