/*************************************************************************/
/*	> File Name: main.c */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Thu 08 Apr 2021 09:28:20 PM CST */
/************************************************************************/
#include "inner_interface_init.h"
#include "APIs.h"

#ifdef __cplusplus
extern "C"{
#endif

int main(int argc, char **argv){
	int verbose = LOGLEVEL_ERROR;
	Args args;
	InjWrapper *obj = NULL;
	do{
		FILTERCF(InjParseArgs(argc, argv, &args) != RESCODE_SUCCESS, verbose, break);
		InjShowArgs(&args);
		verbose = args.iVerbose;
		FILTERCF(InjCreateObj(&obj, &args, args.iVerbose) != RESCODE_SUCCESS, verbose, break);
		if(args.stExportFile.isset ) FILTERCF(InjExportSymTab(obj, verbose) != RESCODE_SUCCESS, verbose,LOG(ERROR "export symbols fail\n"));
		if(args.stFrame.u.addr) FILTERCF(InjBackTrace(obj, verbose) != RESCODE_SUCCESS, verbose, LOG(ERROR "backtrace fail\n"));
		if(args.pcSoName != NULL) FILTERCF(InjPushSoLib(obj, verbose) != RESCODE_SUCCESS, verbose, LOG(ERROR "insert library fail\n"));
		if(args.stStub.now != NULL) FILTERCF(InjStubFunc(obj, verbose) != RESCODE_SUCCESS, verbose, LOG(ERROR "stub fail\n"));
		if(args.stMem.addr) FILTERCF(InjDumpBlock(obj, verbose) != RESCODE_SUCCESS, verbose, LOG(ERROR "dump memory fail\n"));
		if(args.stSetPc.u.addr) FILTERCF(InjSetExecPtr(obj, verbose) != RESCODE_SUCCESS, verbose, LOG(ERROR "set pc fail\n"));
		if(args.stTestFunc.u.addr) FILTERCF(InjTestFunc(obj, verbose) != RESCODE_SUCCESS, verbose, LOG(ERROR "test function fail\n"));
	}while(0);

	InjDeleteArgs(&args);
	FILTERCF(InjDeleteObj(&obj, verbose) != RESCODE_SUCCESS, verbose, 
			if(verbose >= LOGLEVEL_WARN) LOG(WARN "object delete fail, might memory leak\n"));
	if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "all done\n");
	return 0;
}

#ifdef __cplusplus
}
#endif
