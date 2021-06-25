##########################################################################
# File Name: clear.sh
# Author: PilotPaul
# mail: ass163@qq.com
# Created Time: Sun 18 Apr 2021 10:32:05 PM CST
#########################################################################
#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/src/gcc/gcc-6.4.0
export PATH
find . -name *.o -exec rm -f {} \;
find . -name *.a -exec rm -f {} \;
find . -name Makefile -exec rm -f {} \;
find . -name Makefile.in -exec rm -f {} \;
find . -name configure -exec rm -f {} \;
rm -f src/inject
 rm -f injector/log/*
find . -name aclocal.m4 -exec rm -f {} \;
find . -name depcomp -exec rm -f {} \;
find . -name install-sh -exec rm -f {} \;
find . -name ltmain.sh -exec rm -f {} \;
find . -name missing -exec rm -f {} \;
find . -name "config.*" -exec rm -f {} \;
find . -name "autom4te.cache" -print | xargs rm -rf
find . -name ".deps" -print | xargs rm -rf
rm -f stamp-h1
