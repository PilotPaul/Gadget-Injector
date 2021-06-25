CFLAGS+=-fvisibility=hidden -DINJECTOR_EXPORT

#projectlibdir=$(libdir)
#projectlib_LTLIBRARIES=libinjector.so
#libinjector_so_SOURCES=$(top_srcdir)/base/base.c \
#					   $(top_srcdir)/parse/parse.c \
#					   $(top_srcdir)/ptrace/inner_interface_ptrace.c \
#					   $(top_srcdir)/load/inner_interface_init.c
#libinjector_so_LDFLAGS=-shared

lib_LTLIBRARIES=libinjector.la
libinjector_la_SOURCES=$(TOP_PATH)/base/base.c \
					   $(TOP_PATH)/parse/parse.c \
					   $(TOP_PATH)/ptrace/inner_interface_ptrace.c \
					   $(TOP_PATH)/load/inner_interface_init.c \
					   $(TOP_PATH)/load/APIs.c
