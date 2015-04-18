# Process this file with automake to produce Makefile.in.
INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ $(LOCAL_OPTS) -DSYSCONFDIR=\"$(sysconfdir)/\"
sbin_PROGRAMS = brctld
brctld_SOURCES = brctld_main.c brctld_zebra.c brctld_vty.c libbridge_init.c 
LIBS = @LIBS@ @CURSES@ @LIBPAM@
#noinst_HEADERS = mplsadmd.h
brctld_LDADD = -L../lib -lzebra @LIBCAP@
