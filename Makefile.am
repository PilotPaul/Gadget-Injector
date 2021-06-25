if INJECTOR_SHARED
# generate dynamic library in one package
SUBDIRS=lib
else
# generate static libraries respectively
SUBDIRS=base parse ptrace load
endif
SUBDIRS+=src
TOP_PATH=$(shell /bin/pwd)
INCLUDES=-I$(TOP_PATH)/base/include -I$(TOP_PATH)/ptrace/include -I$(TOP_PATH)/load/include -I$(TOP_PATH)/include
export INCLUDES
export TOP_PATH
