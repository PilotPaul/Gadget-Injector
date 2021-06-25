##########################################################################
# File Name: build.sh
# Author: PilotPaul
# mail: ass163@qq.com
# Created Time: Tue 06 Apr 2021 11:05:51 PM CST
#########################################################################
#!/bin/bash

rm -f src/inject
# make configure file in directory 'lib' in advance
if [[ $1 = "shared" ]]; then
	cd lib
	libtoolize -f -c
	aclocal
	autoheader
	autoconf
	automake --add-missing
	cd ..
fi
aclocal
autoheader
autoconf
automake --add-missing
if [[ $1 = "shared" ]]; then
	./configure --enable-shared=yes --enable-debug=yes
else
	./configure --enable-shared=no
fi
# make and install 
make
make install
make distclean
#make tar
