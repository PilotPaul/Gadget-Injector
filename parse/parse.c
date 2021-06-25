/*************************************************************************/
/*	> File Name: parse.c */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Sat 27 Mar 2021 04:29:22 PM CST */
/************************************************************************/
#include "base.h"
#include "APIs.h"
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C"{
#endif
//parse command line,
static uintptr_t HexStr2Uinp(char *str);
API_PUBLIC ResCode InjParseArgs(int argc, char **argv, Args *args){
	ResCode res = RESCODE_FAIL;
	int i;
	int ch;
	int verbose = 0;
	char *file = NULL;
	Args *this = args;
	struct stat statbuf;
	errno = 0;
	memset(args, 0, sizeof(Args));
	FILTERCF(argc < 2, verbose, LOG(ERROR "too few arguments\n"); goto help);
	while((ch = getopt(argc, argv, "hVv::O::f:s:m:p:i:t:")) != -1){
		switch(ch){
			case 'v': verbose += optarg ? (int)strnlen(optarg, 5) : 1; break;
			case 'O':
				file = this->stExportFile.filename;
				if(file != NULL){ free(file); this->stExportFile.filename = 0; } 
				if(optarg){
					FILTERC((file = strdup(optarg)) == NULL, verbose, RESCODE_FAIL_ALLOC, goto out);
					this->stExportFile.filename = file;
				}
				this->stExportFile.isset = 1;
				break;
			case 'f':
				if(this->stFrame.isalloc) { free(this->stFrame.u.func); this->stFrame.u.func = 0; this->stFrame.isalloc = 0; } 
				if(optarg[0] == '0' && (optarg[1] == 'X' || optarg[1] == 'x')){
					FILTERC((this->stFrame.u.addr = HexStr2Uinp(optarg+2)) == 0, verbose, RESCODE_FAIL_NODIGIT,
						   LOG(ERROR "invalid address, try again\n"); goto help);
				}
				else{
					FILTERC((this->stFrame.u.func = strdup(optarg)) == NULL, verbose, RESCODE_FAIL_ALLOC, goto help);
					this->stFrame.isalloc = 1;
				}
				break;
			case 's':
				if(this->stStub.ori){ free(this->stStub.ori), this->stStub.ori = 0; } 
				if(this->stStub.now){ free(this->stStub.now), this->stStub.now = 0; } 
				for(i = (int)strlen(optarg); i >= 0 && optarg[i] != ' '; --i){};
				FILTERCF(i <= 0, verbose, LOG(ERROR "leak of arguments, try again\n"); goto help);
				optarg[i] = '\0';
				this->stStub.ori = strdup(optarg);
				optarg[i] = ' ';
				while(optarg[i] == ' ') ++i;
				FILTERCF(i <= 0 || strlen(optarg+i) == 0, verbose, LOG(ERROR "leak of arguments, try again\n"); goto help);
				this->stStub.now = strdup(optarg+i);
				FILTERC(this->stStub.ori == NULL || this->stStub.now == NULL, verbose, RESCODE_FAIL_ALLOC, goto help);
				break;
			case 'm':
				for(i = (int)strlen(optarg); i >= 0 && optarg[i] != ' '; --i){};
				FILTERCF(i <= 0, verbose, LOG(ERROR "leak of arguments, try again\n"); goto help);
				optarg[i] = '\0';
				if(optarg[0] == '0' && (optarg[1] == 'X' || optarg[1] == 'x')){
					FILTERC((this->stMem.addr = HexStr2Uinp(optarg+2)) == 0, verbose, RESCODE_FAIL_NODIGIT,
							LOG(ERROR "invalid address, try again\n"); goto help);
				}
				else FILTERCF(1, verbose, LOG(ERROR "invalid arguments, try again\n"); goto help);
				optarg[i] = ' ';
				while(optarg[i] == ' ') ++i;
				FILTERCF(i <= 0 || strlen(optarg+i) == 0, verbose, LOG(ERROR "leak of arguments, try again\n"); goto help);
				FILTERC((this->stMem.len = atoi(optarg+i)) == 0 || errno, verbose, RESCODE_FAIL_NODIGIT, 
					   LOG(ERROR "invalid arguments, try again\n"); goto help);
				break;
			case 'M': //to do
				if(this->pcSymbol != NULL) free(this->pcSymbol);
				FILTERC((this->pcSymbol = strdup(optarg)) == NULL, verbose, RESCODE_FAIL_ALLOC, goto help);
				break;
			case 'p':
				if(this->stSetPc.isalloc){ free(this->stSetPc.u.func); this->stSetPc.u.func = 0; this->stSetPc.isalloc = 0; } 
				if(optarg[0] == '0' && (optarg[1] == 'X' || optarg[1] == 'x')){
					FILTERC((this->stSetPc.u.addr = HexStr2Uinp(optarg+2)) == 0, verbose, RESCODE_FAIL_NODIGIT,
						   LOG(ERROR "invalid address, try again\n"); goto help);
				}
				else{
					FILTERC((this->stSetPc.u.func = strdup(optarg)) == NULL, verbose, RESCODE_FAIL_ALLOC, goto help);
					this->stSetPc.isalloc = 1;
				}
				break;
			case 'i':
				if(this->pcSoName != NULL) free(this->pcSoName);
				FILTERCF(stat(optarg, &statbuf) < 0 , verbose, LOG("dynamic library not exist\n"); goto help);
				FILTERC((this->pcSoName = strdup(optarg)) == NULL, verbose, RESCODE_FAIL_ALLOC, goto help);
				break;
			case 't':
				if(this->stTestFunc.isalloc) { free(this->stTestFunc.u.func); this->stTestFunc.u.func = 0; this->stTestFunc.isalloc = 0; } 
				if(optarg[0] == '0' && (optarg[1] == 'X' || optarg[1] == 'x')){
					FILTERC((this->stTestFunc.u.addr = HexStr2Uinp(optarg+2)) == 0, verbose, RESCODE_FAIL_NODIGIT,
						   LOG(ERROR "invalid address, try again\n"); goto help);
				}
				else{
					FILTERC((this->stTestFunc.u.func = strdup(optarg)) == NULL, verbose, RESCODE_FAIL_ALLOC, goto help);
					this->stTestFunc.isalloc = 1;
				}
				break;
			case 'V': InjPrintVersion(); goto out;
help:
			case 'h':
			default:
				InjPrintHelps(argv[0]);
				goto out;
		}
	}
	do{
		if(optind >= argc){
			LOG("leak of PID, try again\n");
			InjPrintHelps(argv[0]);
			break;
		}
		else{
			FILTERC((this->pid = strtoul(argv[optind], NULL, 10)) == 0, verbose, RESCODE_FAIL, break);
		}
		this->iVerbose = verbose;
		res = RESCODE_SUCCESS;
	}while(0);
out:
	if(res != RESCODE_SUCCESS){
		if(file != NULL) free(file);
		if(this->stFrame.isalloc) free(this->stFrame.u.func);
		if(this->stStub.ori){ free(this->stStub.ori), this->stStub.ori = 0; } 
		if(this->stStub.now){ free(this->stStub.now), this->stStub.now = 0; }
		if(this->pcSymbol){ free(this->pcSymbol); this->pcSymbol = 0; }
		if(this->stSetPc.isalloc){ free(this->stSetPc.u.func); this->stSetPc.u.func = 0; }
		if(this->pcSoName){ free(this->pcSoName); this->pcSoName = 0; }
		if(this->stTestFunc.isalloc){ free(this->stTestFunc.u.func); this->stTestFunc.u.func = 0; }
	}
	return res;
}
static uintptr_t HexStr2Uinp(char *str){
	uintptr_t addr = 0;
	for(char *p = str; *p; ++p){
		char ch = tolower(*p);
		if(ch >= 'a' && ch <= 'f') addr = addr*16 + ch-'a'+10;
		else if(ch >= '0' && ch <= '9') addr = addr*16 + ch-'0';
		else return 0;
	}
	return addr;
}

//show parsed command line respectively,
API_PUBLIC void InjShowArgs(const Args *args){
	LOG("Input arguments showed as followings:\n"
			"PID: %d\n"
			"Verbose Level: %d\n",
			args->pid,
			args->iVerbose
	   );
	if(args->stExportFile.isset) LOG("Export Symbols: %s\n", args->stExportFile.isset ? "yes" : "no");
	if(args->stFrame.u.addr) LOG("Need Backtrace\n");
	if(args->stStub.ori) LOG("Stub %s to %s\n", args->stStub.ori, args->stStub.now);
	if(args->stMem.addr) LOG("Dump value from %#lx to %#lx\n", args->stMem.addr, args->stMem.len);
	if(args->stSetPc.u.addr) LOG("Set pc to %#lx\n", args->stSetPc.u.addr);
	if(args->pcSymbol) LOG("Dump symbol [%s]\n", args->pcSymbol);
	if(args->pcSoName) LOG("Inject so library [%s]\n", args->pcSoName);
	if(args->stTestFunc.isalloc){ LOG("Test symbol [%s]\n", args->stTestFunc.u.func); } 
	else if(args->stTestFunc.u.addr) LOG("Test symbol at address [%#lx]\n", args->stTestFunc.u.addr);
}

#ifdef __cplusplus
}
#endif
