/*************************************************************************/
/*	> File Name: APIs.h */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Sat 27 Mar 2021 11:40:17 AM CST */
/************************************************************************/
#ifndef APIS_H_
#define APIS_H_

#include "base.h"

#ifdef __cplusplus
extern "C"{
#endif
API_PUBLIC void InjPrintHelps(const char *cmd);	//helps manual(-h),
API_PUBLIC void InjPrintVersion(void);	//output injector's version(-V),
API_PUBLIC ResCode InjExportSymTab(InjWrapper *wrapper, int verbose);	//export symbols table(-o/-O),
API_PUBLIC ResCode InjBackTrace(InjWrapper *wrapper, int verbose);	//print backtrace of target function(-f),
API_PUBLIC ResCode InjStubFunc(InjWrapper *wrapper, int verbose);	//stub function(-s),
API_PUBLIC ResCode InjDumpBlock(InjWrapper *wrapper, int verbose);	//dump memory block(-m),
API_PUBLIC ResCode InjDumpStruct(InjWrapper *wrapper, int verbose);	//dump complicated symbols value(-M), to do
API_PUBLIC ResCode InjSetExecPtr(InjWrapper *wrapper, int verbose);	//set execute pointer(-p),
API_PUBLIC ResCode InjPushSoLib(InjWrapper *wrapper, int verbose);	//inject shared library into process(-i),
API_PUBLIC ResCode InjTestFunc(InjWrapper *wrapper, int verbose);	//test a function we can use(-t), only support symbol without input argument right now,
#ifdef __cplusplus
}
#endif

#endif
