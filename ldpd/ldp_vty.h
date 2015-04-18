#ifndef LDP_VTY_H
#define LDP_VTY_H

#include "ldp_interface.h"

int ldp_interface_config_write(struct vty *vty);
void ldp_vty_show_init();
void ldp_vty_if_init();
void ldp_vty_init();

#define VTY_GET_UINT32(NAME,V,STR)                                            \
{                                                                             \
  char *endptr = NULL;                                                        \
  (V) = strtoul ((STR), &endptr, 10);                                         \
  if (*endptr != '\0' || ((V) == ULONG_MAX && errno == ERANGE))               \
    {                                                                         \
      vty_out (vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);              \
      return CMD_WARNING;                                                     \
    }                                                                         \
}

#define VTY_GET_UINT32_RANGE(NAME,V,STR,IMIN,IMAX)                            \
{                                                                             \
  VTY_GET_UINT32(NAME,V,STR);                                                 \
  if (((V) < IMIN) || ((V) > IMAX))                                           \
    {                                                                         \
      vty_out (vty, "%% Invalid %s value.  Valid range is (%d ... %d)%s",     \
         NAME, IMIN, IMAX, VTY_NEWLINE);                                      \
      return CMD_WARNING;                                                     \
    }                                                                         \
}

#define VTY_GET_IPV4_ADDRESS(NAME,V,STR)                                      \
{                                                                             \
  struct in_addr addr;							      \
  int retv;                                                                   \
  retv = inet_aton ((STR), &addr);                                            \
  if (!retv)                                                                  \
    {                                                                         \
      vty_out (vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);              \
      return CMD_WARNING;                                                     \
    }                                                                         \
  (V) = ntohl(addr.s_addr);						      \
}

#endif
