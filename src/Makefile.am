bin_PROGRAMS=inject
inject_SOURCES=main.c
if INJECTOR_SHARED
CFLAGS+=-DINJECTOR_EXPORT
#LIBS+=-Wl,-rpath=$(top_srcdir)/lib/lib -L$(top_srcdir)/lib/lib -linjector
#inject_LDFLAGS=-Wl,-rpath=$(top_srcdir)/lib/lib
#inject_LDADD=-L$(top_srcdir)/lib/lib -linjector
inject_LDFLAGS=-Wl,-rpath=$(libdir)
inject_LDADD=-L$(libdir) -linjector
else
inject_LDADD=-L$(top_srcdir)/base/ \
	 -L$(top_srcdir)/parse/ \
	 -L$(top_srcdir)/ptrace/ \
	 -L$(top_srcdir)/load/ \
	 -lload -lparse -lptrace -lbase 
endif
