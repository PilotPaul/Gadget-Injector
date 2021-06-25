/*************************************************************************/
/*	> File Name: APIs.c */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Sat 27 Mar 2021 05:14:43 PM CST */
/************************************************************************/
#include "base.h"
#include "inner_interface_init.h"
#include "inner_interface_ptrace.h"

#ifdef __cplusplus
extern "C"{
#endif
//helps manual(-h),
API_PUBLIC void InjPrintHelps(const char *cmd){
	LOG(
	"Brief of Injector showed followings: [ADDR must start with 0x or 0X, LEN must be a decimal]\n"
	"Usage: %s [OPTIONS] PID\n"
	"OPTIONS:\n"
	" -v[vvvv]                        enable verbose debug information, push it ahead of other options to get all details\n"
	" -h                              usage man of this gadget\n"
	" -O[FILE]                        export all symbols you can use in this process\n"
	" -f ADDR/FUNC-NAME               output functions called backtrace\n"
	" -s \"FUNC-NAME1 FUNC-NAME2\"      stub function1 with function2\n"
	" -m \"ADDR LEN\"                   output the memory content of space which starts from ADDR and lenght is LEN\n"
	//" -M SYMBOL-NMAE                  output the value of SYMBOL\n" //to do
	" -p ADDR/FUNC-NAME               set pc/rip to ADDR or a start address of a function\n"
	" -i SOLIB                        insert a shared object(*.so) into this process\n"
	" -t ADDR/FUNC-NAME               test a function\n"
	" -V                              version of this gadget\n"
	"\n"
	,cmd
	);
}

//version informaiton(-V),
API_PUBLIC void InjPrintVersion(void){
	LOG(INJ_NAME "%u.%u\n\n", INJ_MAJORVER, INJ_MINORVER);
}

//dump symbols table(-o/-O),
API_PUBLIC ResCode InjExportSymTab(InjWrapper *wrapper, int verbose){
	ResCode res = RESCODE_FAIL;
	FILE *fp = stdout;
	if(wrapper == NULL || wrapper->stSymTab.syms == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, wrapper, wrapper->stSymTab.syms);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		size_t num = wrapper->stSymTab.num;
		SymNode *syms = wrapper->stSymTab.syms;
		const unsigned int *order = wrapper->stSymTab.sortaddr;
		Args *args = &wrapper->stArgs;
		if(args->stExportFile.isset && args->stExportFile.filename){
			fp = fopen(args->stExportFile.filename, "wt+");
			FILTERC(fp == NULL, verbose, RESCODE_FAIL_OPEN, break);
		}
		fprintf(fp, "symbol table showed as:\n");
		for(size_t i = 0; i < num; ++i) fprintf(fp, "#%lu#[ 0x%#lx ] %s (%lu)\n",
				i, syms[order[i]].addr, syms[order[i]].name, syms[order[i]].sz);
		if(fp != stdout) fclose(fp), fp = NULL;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(fp != stdout && fp != NULL) fclose(fp);
	}
	return res;
}

//print backtrace of target function(-f),
//InjLi*
//InjFindSymByName
//InjFindSymByAddr
//InjSftBreak
//InjPrintBt
//InjSftRevert
API_PUBLIC ResCode InjBackTrace(InjWrapper *wrapper, int verbose){
	ResCode res = RESCODE_FAIL;
	String oriintr;
	char isattach = 0;
	Args *args = &wrapper->stArgs;
	uintptr_t tgtaddr = 0;
	struct user oriregs, curregs;
	pid_t pid = args->pid;
	if(wrapper == NULL || wrapper->stSymTab.syms == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, wrapper, wrapper->stSymTab.syms);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		Symbol *symtab = &wrapper->stSymTab;
		AsmCmd *asmcmd = &wrapper->stAsmCmd;
		memset(&oriintr, 0, sizeof(String));
		if(args->stFrame.isalloc) tgtaddr = InjFindSymByName(args->stFrame.u.func, symtab, verbose);
		else{
			tgtaddr = args->stFrame.u.addr;
			if(InjTgtAddrValidate(&wrapper->stLib, tgtaddr, 0, verbose) != RESCODE_SUCCESS){
				LOG(ERROR "invalid target address, out of range\n");
				break;
			}
		}
		FILTERCF(tgtaddr == 0, verbose, LOG(ERROR "invalid symbol, try again\n"); break);
		memset(&oriregs, 0, sizeof(oriregs));
		curregs = oriregs;
		FILTERCF(InjSftBreak(pid, tgtaddr, &asmcmd->sftintr, &oriintr, &oriregs, &curregs, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 1;
		FILTERCF(InjPokeAndPrintBt(pid, symtab, &curregs, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjSftRevert(pid, tgtaddr, &oriintr, &oriregs, verbose), verbose, break);
		isattach = 0;
		free(oriintr.addr), oriintr.addr = 0;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(oriintr.addr) free(oriintr.addr);
		if(isattach) FILTERCF(InjSftRevert(pid, tgtaddr, &oriintr, &oriregs, verbose) != RESCODE_SUCCESS, verbose,
				LOG(WARN "revert context failed, target process may be unstable\n"));
	}
	return res;
}

//stub function(-s),
//InjLi*
//InjFindSymByName
//InjGenAsmJump
API_PUBLIC ResCode InjStubFunc(InjWrapper *wrapper, int verbose){
	ResCode res = RESCODE_FAIL;
	Args *args;
	AsmCmd *asmcmd;
	pid_t pid;
	char isattach = 0;
	if(wrapper == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, wrapper, wrapper->stSymTab.syms);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	args = &wrapper->stArgs;
	asmcmd = &wrapper->stAsmCmd;
	pid = args->pid;
	do{
		Symbol *symtab = &wrapper->stSymTab;
		uintptr_t origaddr = 0, nowaddr = 0;
		FILTERCF((origaddr = InjFindSymByName(args->stStub.ori, symtab, verbose)) == 0, verbose,
			   LOG(ERROR "no symbol named [%s], trye again\n", args->stStub.ori); break);
		FILTERCF((nowaddr = InjFindSymByName(args->stStub.now, symtab, verbose)) == 0, verbose,
			   LOG(ERROR "no symbol named [%s], trye again\n", args->stStub.now); break);
		FILTERCF(InjGenerateAsmCmd(asmcmd, ASMCMD_JUMP, (void*)nowaddr, NULL, verbose) != RESCODE_SUCCESS, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG) InjShowAsmCmd(asmcmd);
		FILTERCF(InjLiAttach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 1;
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "set %d bytes to %p\n", (int)asmcmd->jump.len, asmcmd->jump.addr);
		FILTERCF(InjLiWriteDataOrTxt(pid, FALSE, origaddr, (uintptr_t)asmcmd->jump.addr, asmcmd->jump.len, verbose)
				!= RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiDetach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 0;
		LOG("stub done\n");
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(isattach) InjLiDetach(pid, verbose);
		if(asmcmd->jump.addr) free(asmcmd->jump.addr);
		asmcmd->jump.len = 0;
	}
	return res;
}

//dump memory block(-m),
//InjLi*
API_PUBLIC ResCode InjDumpBlock(InjWrapper *wrapper, int verbose){
	ResCode res = RESCODE_FAIL;
	Args *args;
	int *block = NULL;
	char isattach = 0;
	pid_t pid;
	if(wrapper == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, wrapper, NULL);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	args = &wrapper->stArgs;
	pid = args->pid;
	do{
		uintptr_t tgtaddr = args->stMem.addr;
		size_t len = args->stMem.len;
		if(len % 8) len += (8 - len%8);
		FILTERCF(InjTgtAddrValidate(&wrapper->stLib, tgtaddr, len, verbose) != RESCODE_SUCCESS, verbose,
			LOG(ERROR "invalid target address, out of range\n"); break);
		FILTERC((block = malloc(len)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERCF(InjLiAttach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 1;
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiReadDataOrText(pid, TRUE, tgtaddr, (uintptr_t)block, len, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiDetach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 0;
		LOG("dump block showed:\n");
		for(size_t i = 0; i < len/sizeof(int); i += sizeof(int)){
			LOG("%#lx: %x, %x, %x, %x\n", tgtaddr, block[i], block[i+1], block[i+2], block[i+3]);
			tgtaddr += sizeof(int);
		}
		free(block), block = NULL;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(isattach) InjLiDetach(pid, verbose);
		if(block != NULL) free(block);
	}
	return res;
}

//dump complicated symbols value(-M), to do
API_PUBLIC ResCode InjDumpStruct(InjWrapper *wrapper, int verbose);

//set execute pointer(-p),
//InjLi*
//InjFindSymByName
API_PUBLIC ResCode InjSetExecPtr(InjWrapper *wrapper, int verbose){
	ResCode res = RESCODE_FAIL;
	Args *args;
	char isattach = 0;
	pid_t pid;
	if(wrapper == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, wrapper, NULL);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	args = &wrapper->stArgs;
	pid = args->pid;
	do{
		struct user regs;
		uintptr_t pc = 0;
		Symbol *symtab = &wrapper->stSymTab;
		memset(&regs, 0, sizeof(regs));
		if(args->stSetPc.isalloc) pc = InjFindSymByName(args->stSetPc.u.func, symtab, verbose);
		else{
			pc = args->stSetPc.u.addr;
			if(InjTgtAddrValidate(&wrapper->stLib, pc, 0, verbose) != RESCODE_SUCCESS){
				LOG(ERROR "invalid target address, out of range\n");
				break;
			}
		}
		FILTERCF(pc == 0, verbose, args->stSetPc.isalloc ?
				LOG(ERROR "no symbol named [%s]\n", args->stSetPc.u.func) : 
				LOG(ERROR "no symbol at [%#lx]\n", args->stSetPc.u.addr);
			   	break);
		FILTERCF(InjLiAttach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 1;
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiGetRegs(pid, &regs, verbose) != RESCODE_SUCCESS, verbose, break);
		INJREG_PC(regs) = pc;
		FILTERCF(InjLiSetRegs(pid, &regs, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiDetach(pid, verbose) != RESCODE_SUCCESS, verbose, 
				LOG(WARN "detach failed, target process may be unstable\n"); break);
		isattach = 0;
		LOG("set execute pointer done\n");
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(isattach) InjLiDetach(pid, verbose);
	}
	return res;
}

//inject shared library into process(-i),
//InjLi*
//InjUpdateLibs
//InjMergeSymbols
API_PUBLIC ResCode InjPushSoLib(InjWrapper *wrapper, int verbose){
	ResCode res = RESCODE_FAIL;
	Args *args;
	char isattach = 0;
	Symbol *symtabNew = NULL, *out = NULL;
	pid_t pid;
	if(wrapper == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, wrapper, NULL);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	args = &wrapper->stArgs;
	pid = args->pid;
	do{
		SysFunc *sys = &wrapper->stSysFunc;
		AuxStrs *aux = &wrapper->stAuxStrs;
		uintptr_t sonamepos = (uintptr_t)aux->strs[aux->strnum];
		char *soname = args->pcSoName;
		uintptr_t ret = 0;
		int used = aux->sused[aux->strnum];
		if(used > TARGET_SIZEPERBLK - 64) used = aux->sused[aux->strnum++];
		FILTERCF(aux->strnum >= TARGET_STRS_NUM, verbose, break);

		FILTERCF(InjLiAttach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 1;
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "call dlopen[%#lx](%s, %d)\n", sys->dlopen, soname, (RTLD_GLOBAL | RTLD_NOW));
		FILTERCF(InjLiCall(&ret, verbose, pid, sys->dlopen, sys, &used, soname, sonamepos, (RTLD_GLOBAL | RTLD_NOW))
				!= RESCODE_SUCCESS || ret == 0, verbose, break);
		aux->sused[aux->strnum] = used;
		FILTERCF(InjLiDetach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 0;
		FILTERCF(InjUpdateLibs(&symtabNew, &wrapper->stLib, &wrapper->stExeInfo.prog[1], &wrapper->stSysFunc, pid, verbose)
				!= RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjMergeSymbols(&out, &wrapper->stSymTab, symtabNew, verbose) != RESCODE_SUCCESS, verbose, break);
		free(wrapper->stSymTab.syms);
		free(wrapper->stSymTab.sortaddr);
		free(wrapper->stSymTab.sortname);
		wrapper->stSymTab = *out;
		free(out), out = NULL;
		free(symtabNew->sortaddr), symtabNew->sortaddr = 0;
		free(symtabNew->sortname), symtabNew->sortname = 0;
		free(symtabNew->syms), symtabNew->syms = 0;
		symtabNew->num = 0;
		free(symtabNew), symtabNew = NULL;
		res = RESCODE_SUCCESS;
		LOG("inject done\n");
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(symtabNew != NULL){
			if(symtabNew->syms) free(symtabNew->syms);
			if(symtabNew->sortaddr) free(symtabNew->sortaddr);
			if(symtabNew->sortname) free(symtabNew->sortname);
			symtabNew->syms = NULL;
			symtabNew->num = 0;
			free(symtabNew);
		}
		if(out != NULL){
			if(out->syms) free(out->syms);
			if(out->sortaddr) free(out->sortaddr);
			if(out->sortname) free(out->sortname);
			out->syms = NULL;
			out->num = 0;
			free(out);
		}
		if(isattach) InjLiDetach(pid, verbose);
	}
	return res;
}

//test a function we can use(-t), only support symbol without input argument right now,
//InjLi*
//InjFindSymByName
API_PUBLIC ResCode InjTestFunc(InjWrapper *wrapper, int verbose){
	ResCode res = RESCODE_FAIL;
	Args *args;
	char isattach = 0;
	pid_t pid;
	if(wrapper == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, wrapper, NULL);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	args = &wrapper->stArgs;
	pid = args->pid;
	do{
		uintptr_t ret = 0;
		uintptr_t funcaddr = 0;
		const SymNode *funcnode = NULL;
		SysFunc *sys = &wrapper->stSysFunc;
		if(args->stTestFunc.isalloc) funcaddr = InjFindSymByName(args->stTestFunc.u.func , &wrapper->stSymTab, verbose);
		else{
			funcaddr = args->stTestFunc.u.addr;
			FILTERCF(InjTgtAddrValidate(&wrapper->stLib, funcaddr, 0, verbose) != RESCODE_SUCCESS, verbose,
					LOG(ERROR "invalid address, try again\n"); break);
			FILTERCF((funcnode = InjFindSymByAddr(funcaddr, &wrapper->stSymTab, verbose)) == NULL, verbose,
					LOG(ERROR "no function named [%s]\n", funcnode->name); break);
			funcaddr = funcnode->addr;
		}
		FILTERCF(funcaddr == 0, verbose, LOG(ERROR "no function named [%s]\n", args->stTestFunc.u.func); break);
		FILTERCF(InjLiAttach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 1;
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG)
			LOG(DEBUG "call %s[%#lx]()\n", args->stTestFunc.isalloc ? args->stTestFunc.u.func : funcnode->name, funcaddr);
		FILTERCF(InjLiCall(&ret, verbose, pid, funcaddr, sys, 0) != RESCODE_SUCCESS, verbose, break);
		LOG("call done, return value is: %#lx\n", ret);
		FILTERCF(InjLiDetach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 0;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(isattach) InjLiDetach(pid, verbose);
	}
	return res;
}

#ifdef __cplusplus
}
#endif
