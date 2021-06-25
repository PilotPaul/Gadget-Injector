/*************************************************************************/
/*	> File Name: inner_interface_ptrace.c */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Sat 27 Mar 2021 06:40:41 PM CST */
/************************************************************************/
#include "base.h"
#include "inner_interface_ptrace.h"
#include "inner_interface_init.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#ifdef __cplusplus
extern "C"{
#endif

//PTRACE_ATTACH,
API_PRIVATE ResCode InjLiAttach(pid_t pid, int verbose){
	errno = 0;
	FILTERC(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0, verbose >= LOGLEVEL_DEBUG, RESCODE_FAIL_PTRACE_ATTACH,
			return RESCODE_FAIL_PTRACE_ATTACH);
	return RESCODE_SUCCESS;
}
//PTRACE_CONT,
API_PRIVATE ResCode InjLiContinue(pid_t pid){
	errno = 0;
	CHECK(ptrace(PTRACE_CONT, pid, NULL, NULL) < 0,
			RESCODE_FAIL_PTRACE_CONT, return RESCODE_FAIL_PTRACE_CONT);
	return RESCODE_SUCCESS;
}
//PTRACE_DETACH,
API_PRIVATE ResCode InjLiDetach(pid_t pid, int verbose){
	errno = 0;
	FILTERC(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0, verbose >= LOGLEVEL_DEBUG, RESCODE_FAIL_PTRACE_DETACH,
			return RESCODE_FAIL_PTRACE_DETACH);
	return RESCODE_SUCCESS;
}
//PTRACE_POKEDATA and PTRACE_POKETEXT,
API_PRIVATE ResCode InjLiWriteDataOrTxt(pid_t pid, int isdata, uintptr_t taddr, uintptr_t wdata, size_t len, int verbose){
	enum __ptrace_request request = isdata == TRUE ? PTRACE_POKEDATA : PTRACE_POKETEXT;
	const int step = sizeof(uintptr_t);
	uintptr_t unit = 0;
	char *dst = (char*)&unit;
	size_t i = 0, j;
	errno = 0;
	while(i + step <= len){
		for(j = 0; j < step; ++j) *(dst+j) = *((char*)wdata+i+j);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "set %#lx: %#lx\n", taddr+i, unit);
		CHECK(ptrace(request, pid, taddr+i, unit) < 0,
				RESCODE_FAIL_PTRACE_POKE, return RESCODE_FAIL_PTRACE_POKE);
		unit = 0;
		i += step;
	}
	if(i < len){
		for(j = 0; j < len-i; ++j) *(dst+j) = *((char*)wdata+i+j);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "set %#lx: %#lx\n", taddr+i, unit);
		CHECK(ptrace(request, pid, taddr+i, unit) < 0,
				RESCODE_FAIL_PTRACE_POKE, return RESCODE_FAIL_PTRACE_POKE);
	}
	return RESCODE_SUCCESS;
}
//PTRACE_PEEKDATA or PEEKTEXT, former isn't equal to PEEKTXT when get from .txt,
API_PRIVATE ResCode InjLiReadDataOrText(pid_t pid, int isdata, uintptr_t taddr, uintptr_t rdata, size_t len, int verbose){
	enum __ptrace_request request = isdata == TRUE ? PTRACE_PEEKDATA : PTRACE_PEEKTEXT;
	const int step = sizeof(uintptr_t);
	uintptr_t unit = 0;
	char *src = (char*)&unit;
	size_t i = 0, j;
	errno = 0;
	while(i + step <= len){
		CHECK((unit = ptrace(request, pid, taddr+i, NULL)) < 0 || (!unit && errno),
				RESCODE_FAIL_PTRACE_PEEK, return RESCODE_FAIL_PTRACE_PEEK);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "get %#lx: %#lx\n", taddr+i, unit);
		for(j = 0; j < step; ++j) *((char*)rdata+i+j) = *(src+j);
		unit = 0;
		i += step;
	}
	if(i < len){
		CHECK((unit = ptrace(request, pid, taddr+i, NULL)) < 0 || (!unit && errno),
				RESCODE_FAIL_PTRACE_PEEK, return RESCODE_FAIL_PTRACE_PEEK);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "get %#lx: %#lx\n", taddr+i, unit);
		for(j = 0; j < len-i; ++j) *((char*)rdata+i+j) = *(src+j);
	}
	return RESCODE_SUCCESS;
}
//PTRACE_SETREGS,
API_PRIVATE ResCode InjLiSetRegs(pid_t pid, struct user *regs, int verbose){
	errno = 0;
	FILTERC(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0, verbose >= LOGLEVEL_DEBUG, RESCODE_FAIL_PTRACE_SETREG,
			LOG(ERROR "can't set reg context of target process right now, check its status please\n");
			return RESCODE_FAIL_PTRACE_SETREG);
	return RESCODE_SUCCESS;
}
//PTRACE_GETREGS,
API_PRIVATE ResCode InjLiGetRegs(pid_t pid, struct user *orig, int verbose){
	errno = 0;
	FILTERC(ptrace(PTRACE_GETREGS, pid, NULL, orig) < 0, verbose >= LOGLEVEL_DEBUG, RESCODE_FAIL_PTRACE_GETREG, 
			LOG(ERROR "can't get reg context of target process right now, check its status please\n");
			return RESCODE_FAIL_PTRACE_GETREG);
	return RESCODE_SUCCESS;
}
//waitpid, can't use WNOHANG in this case, it must be blocking mode
API_PRIVATE ResCode InjLiWait(pid_t pid, int verbose){
	int status = 0;
	if(waitpid(pid, &status, WUNTRACED) < 0){
		FILTERC(1, verbose, RESCODE_FAIL_WAIT);
		return RESCODE_FAIL;
	}
	else if(WIFSIGNALED(status) || WIFEXITED(status)){
		LOG(ERROR "process [%d] no longer exist\n", pid);
		return RESCODE_FAIL;
	}
	return RESCODE_SUCCESS;
}

/* call in target process, "..." means variable argument lists with zero or more arguments 
 * require: InjLi*
 * 
 * ret: return value of invoking
 * func: the funcition you wanna call
 * ...: variable-length input parameter, each showed as followings
 *  (1)SysFunc*
 *  (2)int *pused: space have already used in this memory block if any
 *  (3)char *s1, *s2, ..., *sn: string type relative input parameter if any
 *  (4)addr1, addr2, ..., addrn: target space to store string where we've allocated in advance if (3) exist
 *  (5)arg1, arg2, ..., argn: 6 parameters at most for system functions
 *  (6)n, arg1, arg2, ..., argn: n(n <=6 ) parameters at most for customed functions, like symbol of inserted so libriaries
 * */
#define INJ_SETCONWAITGET(){ \
	FILTERCF(InjLiSetRegs(pid, &cur, verbose) != RESCODE_SUCCESS, verbose, break); \
	FILTERCF(InjLiContinue(pid) != RESCODE_SUCCESS, verbose, break); \
	FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break); \
	FILTERCF(InjLiGetRegs(pid, &cur, verbose) != RESCODE_SUCCESS, verbose, break); \
	if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "call done, ret: %#lx\n", INJREG_AX(cur)); \
}
API_PRIVATE ResCode InjLiCall(uintptr_t *ret, int verbose, pid_t pid, uintptr_t func, ...){
	ResCode res = RESCODE_FAIL;
	Params paralist;
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		struct user oriregs, cur;
		SysFunc *callset = NULL;
		uintptr_t saved = 0;
		va_start(ap, func);
		callset = va_arg(ap, SysFunc*);
		memset(&oriregs, 0, sizeof(oriregs));
		FILTERCF(InjLiGetRegs(pid, &oriregs, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjPrepareFuncAndPara(&paralist, ap, callset, func, pid, verbose) != RESCODE_SUCCESS, verbose, break);
		va_end(ap);

		cur = oriregs;
		INJREG_SP(cur) -= RED_ZONE;
		INJREG_PC(cur) = func;
		INJREG_AX(cur) = 0;
		//prepare artificial semaphore for 'wait'
		FILTERCF(InjLiReadDataOrText(pid, TRUE, INJREG_SP(cur), (uintptr_t)&saved, sizeof(saved), verbose) != RESCODE_SUCCESS, verbose,break);
		FILTERCF(InjLiWriteDataOrTxt(pid, TRUE, INJREG_SP(cur), (uintptr_t)&null, sizeof(null), verbose) != RESCODE_SUCCESS, verbose, break);

		if(func == callset->alloc || func == callset->free || func == callset->fclose || func == callset->dlclose){
			INJREG_A1(cur) = paralist.params[0];
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "call func[%#lx](%#lx)\n", INJREG_PC(cur), INJREG_A1(cur));
			INJ_SETCONWAITGET();
			if(ret != NULL){
				if(func == callset->free) *ret = 0;
				else *ret = INJREG_AX(cur);
			}
		}
		//single input parameter at target process
		else if(func == callset->strlen){
			INJREG_A1(cur) = paralist.params[0];
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "call func[%#lx](%#lx)\n", INJREG_PC(cur), INJREG_A1(cur));
			INJ_SETCONWAITGET();
			if(ret != NULL) *ret = INJREG_AX(cur);
		}
		//two input parameters
		else if(func == callset->dlopen || func == callset->fopen){
			INJREG_A1(cur) = paralist.params[0];
			INJREG_A2(cur) = paralist.params[1];
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "call func[%#lx](%#lx, %#lx)\n", INJREG_PC(cur), INJREG_A1(cur), INJREG_A2(cur));
			INJ_SETCONWAITGET();
			if(ret != NULL) *ret = INJREG_AX(cur);
		}
		//muti input parameters: local control-string(fmt), target address to store strings, para1, para2, para3...
		else if(func == callset->printf){
			int i = 0, num = paralist.num;
			if(i < num){ INJREG_A1(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A2(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A3(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A4(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A5(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A6(cur) = paralist.params[i++]; }
			INJ_SETCONWAITGET();
			if(ret != NULL) *ret = INJREG_AX(cur);
		}
		//more multi input paraters
		else if(func == callset->fprintf){}
		//extensively compound input paraters
		else if(func == callset->system){}
		else{
			int i = 0, num = paralist.num;
			if(i < num){ INJREG_A1(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A2(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A3(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A4(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A5(cur) = paralist.params[i++]; }
			if(i < num){ INJREG_A6(cur) = paralist.params[i++]; }
			INJ_SETCONWAITGET();
			if(ret != NULL) *ret = INJREG_AX(cur);
		}
		//revert stack and context
		FILTERCF(InjLiWriteDataOrTxt(pid, TRUE, INJREG_SP(oriregs)+RED_ZONE, (uintptr_t)&saved, sizeof(saved), verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiSetRegs(pid, &oriregs, verbose) != RESCODE_SUCCESS, verbose, break);
		free(paralist.params), paralist.params = 0;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(paralist.params) free(paralist.params);
		va_end(ap);
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "target call finished\n");
	return res;
}
/* match args with funcitons
 * paralist: output parameter list
 * vabgn: variable-length input parameter of InjLiCall
 * func: the function you wanna invoke
 * pid: process identification
 * verbose: omitted
 * vabgn: some other variable-length input parameter
 * */
API_PRIVATE ResCode InjPrepareFuncAndPara(Params *paralist, va_list vabgn, SysFunc *callset, 
		uintptr_t func, pid_t pid, int verbose, ...){
	ResCode res = RESCODE_FAIL;
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		memset(paralist, 0, sizeof(Params));
		//single input parameter at this process
		if(func == callset->alloc || func == callset->free || func == callset->fclose || func == callset->dlclose){
			CHECK((paralist->params = malloc(sizeof(uintptr_t))) == NULL, RESCODE_FAIL_ALLOC, break);
			paralist->params[0] = va_arg(vabgn, uintptr_t);
			paralist->num = 1;
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "A1: %#lx\n", paralist->params[0]);
		}
		//single input parameter at target process
		else if(func == callset->strlen){
			CHECK((paralist->params = malloc(sizeof(uintptr_t))) == NULL, RESCODE_FAIL_ALLOC, break);
			paralist->params[0] = va_arg(vabgn, uintptr_t);
			paralist->num = 1;
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "A1: %#lx\n", paralist->params[0]);
		}
		//two input parameters
		else if(func == callset->dlopen || func == callset->fopen){
			int *pused = va_arg(vabgn, int*);
			char *str = va_arg(vabgn, char*);
			uintptr_t tgtaddr = va_arg(vabgn, uintptr_t);
			int arg2 = va_arg(vabgn, int);
			int len = strlen(str) + 1;

			if(func == callset->dlopen){
				CHECK((paralist->params = malloc(2 * sizeof(uintptr_t))) == NULL, RESCODE_FAIL_ALLOC, break);
				FILTERCF(len >= TARGET_SIZEPERBLK - *pused, verbose, break);
				if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "set %d bytes to %#lx\n", (int)len, tgtaddr + *pused);
				FILTERCF(InjLiWriteDataOrTxt(pid, TRUE, tgtaddr + *pused, (uintptr_t)str, len, verbose)
						!= RESCODE_SUCCESS, verbose, break);
				if(len % 8) len += (8 - len%8);
				else len += 8;
				paralist->params[0] = tgtaddr + *pused;
				paralist->params[1] = arg2;
				*pused += len;
			}
			else if(func == callset->fopen){}//to do
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "A1: %s, A2: %d\n", str, arg2);
			paralist->num = 2;
		}
		//muti input parameters: local control-string(fmt), target address to store strings, para1, para2, para3...
		else if(func == callset->printf){
			int *pused = va_arg(vabgn, int*);
			int num = 1;
			char *fmt = va_arg(vabgn, char*);
			uintptr_t tgtaddr = va_arg(vabgn, uintptr_t);
			char *tmp;
			int used = 0;
			int remaint = TARGET_SIZEPERBLK - *pused;
			int len = strlen(fmt);
			if(len % 8) len += (8 - len%8);
			CHECK((paralist->params = malloc(sizeof(uintptr_t))) == NULL, RESCODE_FAIL_ALLOC, break);
			FILTERCF(len >= remaint, verbose, break);
			FILTERCF(InjLiWriteDataOrTxt(pid, TRUE, tgtaddr + *pused, (uintptr_t)fmt, len, verbose) != RESCODE_SUCCESS, verbose, break);
			paralist->params[0] = tgtaddr;
			remaint -= len;
			used += len;
			*pused += used;
			for(char *p = fmt; *p && num < INJ_MAX_PARAMS; ++p){
				if(*p == '%'){
					++p;
					switch(*p){
						case 'c': paralist->params[num++] = va_arg(vabgn, int); break;
						case 'x':
						case 'd':
						case 'u': paralist->params[num++] = va_arg(vabgn, int); break;
						case 'p': paralist->params[num++] = va_arg(vabgn, uintptr_t); break;
						case 's': //input parameter is string, we need to write it into target process then obtain a valid addr
								  tmp = va_arg(vabgn, char*);
								  len = strlen(tmp);
								  if(len % 8) len += (8 - len%8);
								  else len += 8; //1 NUL character for terminating string, but at least 8 bytes as operating unit
								  FILTERCF(len >= remaint, verbose, goto out);
								  FILTERCF(InjLiWriteDataOrTxt(pid, TRUE, tgtaddr + *pused, (uintptr_t)tmp, len, verbose)
										  != RESCODE_SUCCESS, verbose, goto out);
								  paralist->params[num++] = tgtaddr + *pused;
								  used += len;
								  remaint -= len;
								  *pused += used;
								  break;
						default: LOG(ERROR "invalid specific type\n"); goto out;
					}
				}
			}
			paralist->num = num;
		}
		//more multi input paraters
		else if(func == callset->fprintf){}
		//extensively compound input paraters
		else if(func == callset->system){}
		//customed function, input parameters must be extended to uintptr_t in advance
		else{
			int n = va_arg(vabgn, int);
			if(n > 0){
				FILTERCF(n > 6, verbose, LOG(ERROR "too many input parameters, trye another function\n"); break);
				CHECK((paralist->params = malloc(n * sizeof(uintptr_t))) == NULL, RESCODE_FAIL_ALLOC, break);
				for(int i = 0; i < n; ++i) paralist->params[i] = va_arg(vabgn, uintptr_t);
			}
			paralist->num = n;
		}
		res = RESCODE_SUCCESS;
	}while(0);
out:
	if(res != RESCODE_SUCCESS){
		if(paralist->params != NULL) free(paralist->params);
	}
	return res;
}

//save process asm code,insert soft interrupt req,
///InjLi*
API_PRIVATE ResCode InjSftBreak(pid_t pid, uintptr_t tgtaddr, String *intr, String *saved,
		struct user *ori, struct user *cur, int verbose){
	ResCode res = RESCODE_FAIL;
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		size_t len = intr->len;
		if(len % 8) len += (8 - len%8);
		memset(saved, 0, sizeof(*saved));
		CHECK((saved->addr = malloc(len)) == NULL, RESCODE_FAIL_ALLOC, break);
		FILTERCF(InjLiAttach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiGetRegs(pid, ori, verbose) != RESCODE_SUCCESS, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "get %d bytes from %#lx\n", (int)len, tgtaddr);
		FILTERCF(InjLiReadDataOrText(pid, FALSE, tgtaddr, (uintptr_t)saved->addr, len, verbose) != RESCODE_SUCCESS, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "set %d bytes to %#lx\n", (int)intr->len, (uintptr_t)tgtaddr);
		FILTERCF(InjLiWriteDataOrTxt(pid, FALSE, tgtaddr, (uintptr_t)intr->addr, intr->len, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiContinue(pid) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiGetRegs(pid, cur, verbose) != RESCODE_SUCCESS, verbose, break);
		saved->len = len;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(saved->addr){ free(saved->addr); saved->addr = 0; } 
		saved->len = 0;
	}
	return res;
}
//revert breakpiont,
API_PRIVATE ResCode InjSftRevert(pid_t pid, uintptr_t tgtaddr, String *oriintr, struct user *oriregs, int verbose){
	ResCode res = RESCODE_FAIL;
	char isattach = 1;
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "set %d bytes to %#lx\n", (int)oriintr->len, (uintptr_t)tgtaddr);
		FILTERCF(InjLiWriteDataOrTxt(pid, FALSE, tgtaddr, (uintptr_t)oriintr->addr, oriintr->len, verbose)
				!= RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiSetRegs(pid, oriregs, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiDetach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 0;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(isattach) InjLiDetach(pid, verbose);
	}
	return res;
}
//print out the calling backtrace,
///InjLi*
API_PRIVATE ResCode InjPokeAndPrintBt(pid_t pid, Symbol *symtab, struct user *regs, int verbose){
	ResCode res = RESCODE_FAIL;
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		uintptr_t rbp = INJREG_BP(*regs), pre = 0;
		//[rbp]: base pointer of previous frame, that is previous frame's rbp -- info[0]
		//[rbp+8]: return address of current frame, that is previous frame's rip -- info[1]
		uintptr_t info[2] = { 0 };
		uintptr_t bt[MAX_DEPTH] = { 0 };
		int top = 0;
		bt[top++] = INJREG_PC(*regs); //next executing assembly code's address
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "get %d bytes from %#lx\n", (int)(2*sizeof(uintptr_t)), rbp);
		FILTERCF(InjLiReadDataOrText(pid, TRUE, rbp, (uintptr_t)info, 2*sizeof(uintptr_t), verbose) != RESCODE_SUCCESS, verbose, break);
		while(*info && pre != *info){ //avoid inifinite loop
			bt[top++] = info[1];
			pre = info[0];
			info[1] = info[0] = 0;
			rbp = pre;
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "get %d bytes from %#lx\n", (int)(2*sizeof(uintptr_t)), rbp);
			FILTERCF(InjLiReadDataOrText(pid, TRUE, rbp, (uintptr_t)info, 2*sizeof(uintptr_t), verbose) != RESCODE_SUCCESS, verbose, goto out);
		}
		LOG("backtrace showed as followings:\n");
		for(int i = 0; i < top; ++i){
			const SymNode *func = InjFindSymByAddr(bt[i], symtab, verbose);
			FILTERCF(func == NULL, verbose, goto out);
			LOG("#%d\t%#lx %s(+%lu)\n", i, func->addr, func->name, bt[i] - func->addr);
		}
		res = RESCODE_SUCCESS;
	}while(0);
out:
	return res;
}

#ifdef __cplusplus
}
#endif
