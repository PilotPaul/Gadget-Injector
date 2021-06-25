/*************************************************************************/
/*	> File Name: base.c */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Sat 27 Mar 2021 03:34:23 PM CST */
/************************************************************************/
#include "base.h"

#ifdef __cplusplus
extern "C"{
#endif
VAR_PRIVATE va_list ap;
VAR_PRIVATE const char sp[2] = " ";
VAR_PRIVATE const char dash[2] = "-";
VAR_PRIVATE const char newline[2] = "\n";
VAR_PRIVATE const char colon[2] = ":";
VAR_PRIVATE const uintptr_t null = 0;
VAR_PUBLIC char *ResStr[] = {	//suit with enum ResCode
	INFO "[%s:%u]success\n",	//0
	ERROR "[%s:%u]failed\n",	//1
	ERROR "[%s:%u]memory alloc failed as %s\n",	//2
	ERROR "[%s:%u]open file failed as %s\n",	//3
	ERROR "[%s:%u]read failed as %s\n",	//4
	ERROR "[%s:%u]seek failed as %s\n",	//5
	ERROR "[%s:%u]ptrace attach failed as %s\n",	//6
	ERROR "[%s:%u]ptrace detach failed as %s\n",	//7
	ERROR "[%s:%u]ptrace poke failed as %s\n",	//8
	ERROR "[%s:%u]ptrace peek failed as %s\n",	//9
	ERROR "[%s:%u]ptrace setregs failed as %s\n",	//10
	ERROR "[%s:%u]ptrace getregs failed as %s\n",	//11
	ERROR "[%s:%u]ptrace continue failed as %s\n",	//12
	ERROR "[%s:%u]wait failed as %s\n",	//13
	ERROR "[%s:%u]invalid numerics\n",	//14
	ERROR "[%s:%u]invalid arguments, left-->right: %p, %p\n",	//15
	ERROR "[%s:%u]strtok failed as %s\n",	//16
	ERROR "[%s:%u]mkdir failed as %s\n",	//17
	ERROR "[%s:%u]rmove failed as %s\n",	//18
};
#ifdef __cplusplus
}
#endif
