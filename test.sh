##########################################################################
# File Name: test.sh
# Author: PilotPaul
# mail: ass163@qq.com
# Created Time: Sat 10 Apr 2021 10:14:51 PM CST
#########################################################################
#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/src/gcc/gcc-6.4.0
export PATH

if [ x$1 = xleakcheck ]; then
	VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
	echo "$VALGRIND"
fi
# test functionalities
#echo "=======================1. no argument===================="
#${VALGRIND} inject

#echo "=======================2. with verbose======================="
#${VALGRIND} inject -vvvvv

#echo "=======================3. show version======================="
#${VALGRIND} inject -V

#echo "=======================4. show help======================="
#${VALGRIND} inject -vvvvv -h
#${VALGRIND} inject -h

#echo "=======================5. with verbose and pid======================="
#${VALGRIND} inject -vvvvv `pidof test`
#${VALGRIND} inject `pidof test`

#echo "=======================6. with verbose, pid, output symbols to stdout======================="
#${VALGRIND} inject -O -vvvvv `pidof test`
#${VALGRIND} inject -O `pidof test`

#echo "=======================7. with verbose, pid, output symbols to file======================="
#rm -f log/symbols.log
#${VALGRIND} inject -Olog/symbols.log -vvvvv `pidof test`
#${VALGRIND} inject -Olog/symbols.log `pidof test`

#echo "=======================8. with verbose, pid, bt with name======================="
#${VALGRIND} inject -f invalid -vvvvv `pidof test`
#${VALGRIND} inject -f invalid `pidof test`
#${VALGRIND} inject -f func2 -vvvvv `pidof test`
#${VALGRIND} inject -f func2 `pidof test`

#echo "=======================9. with verbose, pid, bt with addr======================="
#${VALGRIND} inject -f 0x400578454856561 -vvvvv `pidof test`
#${VALGRIND} inject -f 0x400578454856561 `pidof test`
#${VALGRIND} inject -vvvvv -f 0x400580 `pidof test`
#${VALGRIND} inject -f 0x400580 `pidof test`
#${VALGRIND} inject -f 0x40058d `pidof test`
#${VALGRIND} inject -vvvvv -f 0X0 `pidof test`
#${VALGRIND} inject -f 0X0 `pidof test`

#echo "=======================10. with verbose, pid, inject so lib======================="
#${VALGRIND} inject -vvvvv -i /home/code/case/inject_test/libsub.so `pidof test`
#${VALGRIND} inject -i /home/code/case/inject_test/libsub.so `pidof test`
#${VALGRIND} inject -vvvvv -i libsub.so `pidof test`
#${VALGRIND} inject -i libsub.so `pidof test`

#echo "=======================11. with verbose, pid, stub======================="
#${VALGRIND} inject -vvvvv -s "original invalid" `pidof test`
#${VALGRIND} inject -vvvvv -s "original " `pidof test`
#${VALGRIND} inject -vvvvv -s "original" `pidof test`
#${VALGRIND} inject -vvvvv -s "" `pidof test`
#${VALGRIND} inject -vvvvv -s `pidof test`
#${VALGRIND} inject -s "original invalid" `pidof test`
#${VALGRIND} inject -vvvvv -s "invalid original" `pidof test`
#${VALGRIND} inject -s "invalid original" `pidof test`
#${VALGRIND} inject -vvvvv -s "invalid invalid" `pidof test`
#${VALGRIND} inject -s "invalid invalid" `pidof test`
#${VALGRIND} inject -vvvvv -s "original nextfunc" `pidof test`
#${VALGRIND} inject -s "original nextfunc" `pidof test`
#${VALGRIND} inject -vvvvv -i /home/code/case/inject_test/libsub.so -s "original stubfunc" `pidof test`
#${VALGRIND} inject -i /home/code/case/inject_test/libsub.so -s "original stubfunc" `pidof test`

#echo "=======================12. with verbose, pid, dump block======================="
#${VALGRIND} inject -vvvvv -m "0x1234 6" `pidof test`
#${VALGRIND} inject -m "0x1234 6" `pidof test`
#${VALGRIND} inject -vvvvv -m "0x40058d 17" `pidof test`
#${VALGRIND} inject -m "0x40058d 17" `pidof test`
#${VALGRIND} inject -vvvvv -m "0x40058d 0" `pidof test`
#${VALGRIND} inject -m "0x40058d 0" `pidof test`
#${VALGRIND} inject -vvvvv -m "0x40058d 9999999999" `pidof test`
#${VALGRIND} inject -m "0x40058d 9999999999" `pidof test`
#${VALGRIND} inject -vvvvv -m "0x40058d -9999" `pidof test`
#${VALGRIND} inject -m "0x40058d -9999" `pidof test`
#${VALGRIND} inject -vvvvv -m "0x0 -9999" `pidof test`
#${VALGRIND} inject -m "0x0 -9999" `pidof test`

#echo "=======================13. with verbose, pid, set pc======================="
#${VALGRIND} inject -p invalid -vvvvv `pidof test`
#${VALGRIND} inject -p invalid `pidof test`
#${VALGRIND} inject -p func2 -vvvvv `pidof test`
#${VALGRIND} inject -p func2 `pidof test`

#echo "=======================14. with verbose, pid, bt with addr======================="
#${VALGRIND} inject -p 0x400578454856561 -vvvvv `pidof test`
#${VALGRIND} inject -p 0x400578454856561 `pidof test`
#${VALGRIND} inject -vvvvv -p 0x400580 `pidof test`
#${VALGRIND} inject -p 0x400580 `pidof test`
#${VALGRIND} inject -p 0x40058d `pidof test`
#${VALGRIND} inject -vvvvv -p 0X0 `pidof test`
#${VALGRIND} inject -p 0X0 `pidof test`

#echo "=======================15. with verbose, pid, set pc======================="
#${VALGRIND} inject -t invalid -vvvvv `pidof test`
#${VALGRIND} inject -t invalid `pidof test`
#${VALGRIND} inject -t func2 -vvvvv `pidof test`
#${VALGRIND} inject -t func2 `pidof test`

#echo "=======================16. with verbose, pid, bt with addr======================="
#${VALGRIND} inject -t 0x400578454856561 -vvvvv `pidof test`
#${VALGRIND} inject -t 0x400578454856561 `pidof test`
#${VALGRIND} inject -vvvvv -t 0x400580 `pidof test`
#${VALGRIND} inject -t 0x400580 `pidof test`
#${VALGRIND} inject -t 0x40058d `pidof test`
#${VALGRIND} inject -vvvvv -t 0X0 `pidof test`
#${VALGRIND} inject -t 0X0 `pidof test`
echo "=======================done======================="
