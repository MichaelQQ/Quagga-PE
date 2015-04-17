# Process this file with automake to produce Makefile.in.
INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"
sbin_PROGRAMS = lmd
lmd_SOURCES = lmd_main.c lmd_zebra.c lmd_vty.c lmd.c lmd_lib.c  
LIBS = @LIBS@ @CURSES@ @LIBPAM@
#noinst_HEADERS = mplsadmd.h
lmd_LDADD = -L../lib -lzebra @LIBCAP@
