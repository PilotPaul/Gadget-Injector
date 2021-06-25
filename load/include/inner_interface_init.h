/*************************************************************************/
/*	> File Name: inner_interface_init.h */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Sat 27 Mar 2021 12:06:59 PM CST */
/************************************************************************/
#ifndef INNER_INTERFACE_INIT_H_
#define INNER_INTERFACE_INIT_H_

#include "base.h"

#ifdef __cplusplus
extern "C"{
#endif
API_PUBLIC ResCode InjParseArgs(int argc, char **argv, Args *args);	//parse command line,
API_PUBLIC void InjDeleteArgs(Args *args);
API_PUBLIC void InjShowArgs(const Args *args);	//show parsed command line respectively,
API_PUBLIC ResCode InjCreateObj(InjWrapper **wrapperNew, Args *args, int verbose);	//create object for injector
API_PUBLIC ResCode InjDeleteObj(InjWrapper **wrapper, int verbose);	//delete object for injector

API_PRIVATE ResCode InjOpenFile(int *fd, char *name, int verbose);	//open file wrapper function
API_PRIVATE ResCode InjLoadElf(ElfInfo **elfNew, LibInfo **libinfoNew, Symbol **symtabNew, int fd, pid_t pid, int verbose);	//load elf information,
API_PRIVATE ResCode InjFreeElf(ElfInfo **elf, LibInfo **libinfo, Symbol **symtab, int verbose);	//free elf information,
API_PRIVATE ResCode InjLoadElfHdr(ElfHdr *ehdr, int fd, int verbose);	//load elf header information we interest in,
API_PRIVATE ResCode InjLoadSecHdr(SecHdr **shdrNew, Symbol **symtabNew, ElfInfo *elfinfo, int fd, int verbose);	//load section header information we interest in,
API_PRIVATE ResCode InjLoadProHdr(ProgHdr **phdrNew, unsigned int*phdrnum, ElfHdr *ehdr, int fd, int verbose);	//load program header information we interest in,
API_PRIVATE ResCode InjLoadSymTab(Symbol **symtabNew, Elf_Shdr *symtab, Elf_Shdr *strsh, int fd, int verbose);	//load symbol table according section header,
API_PRIVATE SymType InjGetSymTypeFromInfo(unsigned char info);	//retrieve type of symbol,
API_PRIVATE ResCode InjScanMaps(LibInfo **libsNew, pid_t pid, int verbose);	//scan maps of target process to get dependent libraries,
API_PRIVATE ResCode InjPushLibInfo(LibInfo *libinfo, LibNodes *elem, int verbose); //list node insert to front -- list[0]
API_PRIVATE void InjClearbInfo(LibInfo **libinfo); //destory linked list
API_PRIVATE ResCode InjFindLib(LibNodes **out, LibNodes *libs, char *libname, int verbose); //search so-lib by lib's name
API_PRIVATE ResCode InjParseMapsEntry(LibNodes **libnodeNew, char *entry, pid_t pid, int verbose);	//parse each line of maps,
API_PRIVATE ResCode InjMergeSymbols(Symbol **out, Symbol *symtab1, Symbol *symtab2, int verbose);	//merge symbols,
API_PRIVATE ResCode InjSortSymbols(Symbol *symtab, char is_namebase, char is_acend, int verbose);	//sort symbols by address or name,
API_PRIVATE ResCode InjTgtAddrValidate(const LibInfo *libinfo, uintptr_t tgtaddr, int len, int verbose);	//validate target address valid or not
API_PRIVATE ResCode InjGetSysFuncFromMapsLibs(SysFunc *sysfnNew, LibInfo *libinfo, pid_t pid, int verbose);	//find syscall/C-funcs we need from /prc/PID/maps,
API_PRIVATE uintptr_t InjFindSymByName(char *symname, Symbol *symtab, int verbose);	//search symbol address by name from symbol table
API_PRIVATE const SymNode* InjFindSymByAddr(uintptr_t addr, Symbol *symtab, int verbose);	//search symbol name by address from symbol table
API_PRIVATE FileType InjGetFileType(int e_type);	//convert system filetype to local filetype
API_PRIVATE ResCode InjUpdateLibs(Symbol **symtabNew, LibInfo *libinfo, ProgHdr *dynamic, SysFunc *sys, pid_t pid, int verbose);	//update libinfo for newly pushed library,
API_PRIVATE ResCode InjGetLinkMap(struct link_map *linkmap, ProgHdr *dynamic, pid_t pid, SysFunc *sys, int verbose);	//get link_map of target process in running,
API_PRIVATE ResCode InjGetTargetMemBlk(AuxStrs *auxNew, SysFunc *sys, pid_t pid, int verbose);	//allocate memory in target process,
API_PRIVATE ResCode InjFreeTargetMemBlk(AuxStrs *aux, SysFunc *sys, pid_t pid, int verbose);	//free memory in target process,

API_PRIVATE ResCode InjGenerateAsmCmd(AsmCmd *asmcmdNew, int cmdtype, void *addr, void *data, int verbose);	//generate asm code,
API_PRIVATE ResCode InjGenAsmCom(String *out, void *data, char *asmfile, char *args, char *objname, AsmCmdType type, int verbose);
API_PRIVATE void InjShowAsmCmd(const AsmCmd *asmcmd);	//show asm code,
API_PRIVATE ResCode InjGenAsmJump(String *jmpNew, uintptr_t tgtaddr, AsmCmdType type, int verbose);	//generate soft interrupt,
API_PRIVATE ResCode InjGenAsmSftIntr(String *sftintrNew, AsmCmdType type, int verbose);
API_PRIVATE ResCode InjCallShellCmd(char *shellcmd, char *optargs, char *dir, char *outfile, int *fd, size_t *filesz, int verbose);	//call shell command and output result to outfile,
#ifdef __cplusplus
}
#endif

#endif
