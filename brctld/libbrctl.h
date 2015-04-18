#ifndef LIBBRCTL_H
#define LIBBRCTL_H
//add by here
#include "zebra.h"
#include "command.h"
#include "log.h"
//end by here

int addbr_cmd(const char* brname);
int delbr_cmd(const char* brname);
int addif_cmd(const char* brname,const char*br_if);
int delif_cmd(const char* brname,const char*br_if);
int setageing_cmd(const char* brname,int timer);
int stp_cmd(const char* brname,const char*cmd);

int show_cmd();
int showmacs_cmd(const char* brname);
int showstp_cmd(const char* brname);

#endif
