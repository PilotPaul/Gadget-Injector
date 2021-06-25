/*************************************************************************/
/*	> File Name: inner_interface_init.c */
/*	> Author: PilotPaul */
/*	> Mail: ass163@qq.com */
/*	> Created Time: Sun 28 Mar 2021 12:22:44 PM CST */
/************************************************************************/
#include "base.h"
#include "inner_interface_init.h"
#include "inner_interface_ptrace.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#ifdef __cplusplus
extern "C"{
#endif

//create object for injector,
///InjOpenFile
///InjLoadElf
///InjGetSysFuncFromLib
///InjGetTargetMemBlk
///InjGenerateAsmCmd
///InjShowAsmCmd
API_PUBLIC ResCode InjCreateObj(InjWrapper **wrapperNew, Args *args, int verbose){
	ResCode res = RESCODE_FAIL;
	pid_t pid = args->pid;
	char exefile[EXENAME_LEN];
	int fd = -1;
	ElfInfo *elf = NULL;
	LibInfo *libinfo = NULL;
	Symbol *symtab = NULL;
	InjWrapper *this = NULL;
	if(wrapperNew == NULL || args == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, wrapperNew, args);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	*wrapperNew = NULL;
	do{
		this = malloc(sizeof(InjWrapper));
		FILTERC(this == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memset(this, 0, sizeof(*this));
		FILTERC(snprintf(exefile, EXENAME_LEN, "/proc/%d/exe", pid) < 0, RESCODE_FAIL, verbose, break);
		FILTERCF(InjOpenFile(&fd, exefile, verbose) != RESCODE_SUCCESS, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "loading symbols from [%s]\n", exefile);
		FILTERCF(InjLoadElf(&elf, &libinfo, &symtab, fd, pid, verbose) != RESCODE_SUCCESS, verbose, break);
		close(fd);
		FILTERCF(InjGetSysFuncFromMapsLibs(&this->stSysFunc, libinfo, pid, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjGetTargetMemBlk(&this->stAuxStrs, &this->stSysFunc, pid, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjGenerateAsmCmd(&this->stAsmCmd, ASMCMD_SFTINTR, NULL, NULL, verbose) != RESCODE_SUCCESS, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG) InjShowAsmCmd(&this->stAsmCmd);
		if(elf->shnum){
			free(elf->sec);
			elf->sec = NULL;
			elf->shnum = 0;
		}
		this->stExeInfo.prog = elf->prog;
		this->stExeInfo.phdrnum = elf->phnum;
		this->stArgs = *args;
		this->stLib = *libinfo;
		this->stSymTab = *symtab;
		*wrapperNew = this;
		free(elf);
		free(libinfo);
		free(symtab);
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(fd != -1) close(fd);
		//only free at the most outer when we encounter error, in order to reduce codes
		InjFreeElf(&elf, &libinfo, &symtab, verbose);
		if(this != NULL){
			if(this->stAsmCmd.sftintr.addr) free(this->stAsmCmd.sftintr.addr);
			this->stAsmCmd.sftintr.len = 0;
			InjFreeTargetMemBlk(&this->stAuxStrs, &this->stSysFunc, pid, verbose);
			memset(&this->stSysFunc, 0, sizeof(SysFunc));
			InjDeleteArgs(&this->stArgs);
			free(this);
		}
	}
	return res;
}

//delete object for injector
API_PUBLIC void InjDeleteArgs(Args *args){
	if(args->stExportFile.filename) free(args->stExportFile.filename);
	if(args->stFrame.isalloc) free(args->stFrame.u.func);
	if(args->stStub.now){
		free(args->stStub.now);
		free(args->stStub.ori);
	}
	if(args->pcSoName) free(args->pcSoName);
	if(args->stSetPc.isalloc) free(args->stSetPc.u.func);
	if(args->stTestFunc.isalloc) free(args->stTestFunc.u.func);
	memset(args, 0, sizeof(Args));
}
API_PUBLIC ResCode InjDeleteObj(InjWrapper **wrapper, int verbose){
	ResCode res = RESCODE_FAIL;
	if(wrapper == NULL || *wrapper == NULL){
		if(verbose >= LOGLEVEL_DEBUG) ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, wrapper, *wrapper);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		InjWrapper *obj = *wrapper;
		pid_t pid = obj->stArgs.pid;

		if(obj->stExeInfo.prog){
			free(obj->stExeInfo.prog[0].name.addr);
			free(obj->stExeInfo.prog[1].name.addr);
			free(obj->stExeInfo.prog);
			obj->stExeInfo.prog = 0;
			obj->stExeInfo.phdrnum = 0;
		}

		if(obj->stLib.last.l_name){
			if(obj->stLib.last.l_name) free(obj->stLib.last.l_name);
			obj->stLib.last.l_name = 0;
		}
		if(obj->stLib.nodes){
			LibNodes *cur = obj->stLib.nodes, *next;
			while(cur){
				next = cur->next;
				if(cur->libname) free(cur->libname);
				free(cur);
				cur = next;
			}
			obj->stLib.nodes = 0;
		}
		obj->stLib.num = 0;

		if(obj->stSymTab.syms){
			SymNode *nodes = obj->stSymTab.syms;
			for(int i = 0; i < (int)obj->stSymTab.num; ++i) free(nodes[i].name);
			free(obj->stSymTab.syms);
			obj->stSymTab.syms = 0;
			free(obj->stSymTab.sortaddr);
			obj->stSymTab.sortaddr = 0;
			free(obj->stSymTab.sortname);
			obj->stSymTab.sortname = 0;
			obj->stSymTab.num = 0;
		}

		if(obj->stAsmCmd.num > 0){
			String *asms = &obj->stAsmCmd.sftintr;
			for(int i = 0; i < obj->stAsmCmd.num; ++i) if(asms[i].addr) free(asms[i].addr);
			memset(&obj->stAsmCmd, 0, sizeof(AsmCmd));
		}

		FILTERCF(InjFreeTargetMemBlk(&obj->stAuxStrs, &obj->stSysFunc, pid, verbose) != RESCODE_SUCCESS, verbose,
				LOG(WARN "failed to free target process's memory, memory leak may occur\n"));

		free(obj);
		*wrapper = NULL;
		res = RESCODE_SUCCESS;
	}while(0);
	return res;
}

//free elf information,
API_PRIVATE ResCode InjFreeElf(ElfInfo **elf, LibInfo **libinfo, Symbol **symtab, int verbose){
	if(elf == NULL || libinfo == NULL || symtab == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, elf, libinfo);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	if(*elf != NULL){
		if((*elf)->shnum) free((*elf)->sec); //free as block for allocate as block
		if((*elf)->prog){
			free((*elf)->prog[0].name.addr);
			free((*elf)->prog[1].name.addr);
			free((*elf)->prog);
			(*elf)->prog = 0;
			(*elf)->phnum = 0;
			free((*elf)->prog);
		}
		free(*elf);
		*elf = NULL;
	}
	if(*symtab != NULL){
		SymNode *symarr = (*symtab)->syms;
		for(int i = 0; i < (int)(*symtab)->num; ++i) free(symarr[i].name);
		free(symarr);
		free((*symtab)->sortaddr);
		free((*symtab)->sortname);
		free(*symtab);
		*symtab = NULL;
	}
	if(*libinfo != NULL){
		LibNodes *this = (*libinfo)->nodes;
		while(this != NULL){
			LibNodes *next = this->next;
			free(this->libname);
			free(this);
			this = next;
		}
		free(*libinfo);
		*libinfo = NULL;
	}
	return RESCODE_SUCCESS;
}
//load elf information,
///depend: InjLoadElfHdr
///depend: InjLoadSecHdr
///depend: InjLoadProHdr
///depend: InjScanMaps
///depend: InjSortSymbols
API_PRIVATE ResCode InjLoadElf(ElfInfo **elfNew, LibInfo **libinfoNew, Symbol **symtabNew, int fd, pid_t pid, int verbose){
	int res = RESCODE_FAIL;
	ElfInfo *elf = NULL;
	LibNodes *interp = NULL;
	if(elfNew == NULL || libinfoNew == NULL || symtabNew == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, elfNew, libinfoNew);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	*elfNew = NULL;
	*libinfoNew = NULL;
	*symtabNew = NULL;
	do{
		FILTERC((elf = malloc(sizeof(ElfInfo))) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memset(elf, 0, sizeof(*elf));
		FILTERCF(InjLoadElfHdr(&elf->elf, fd, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLoadSecHdr(&elf->sec, symtabNew, elf, fd, verbose) != RESCODE_SUCCESS, verbose, break);
		if(elf->elf.ftype == FILETYPE_EXEC){
			FILTERCF(InjLoadProHdr(&elf->prog, &elf->phnum, &elf->elf, fd, verbose) != RESCODE_SUCCESS, verbose, break);
			FILTERCF(InjScanMaps(libinfoNew, pid, verbose) != RESCODE_SUCCESS, verbose, break);
			FILTERC((interp = malloc(sizeof(LibNodes))) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
			interp->type = MAPTYPE_SO;
			interp->libname = strdup(elf->prog[0].name.addr);
			interp->dynaddr = 0;
			interp->bgnaddr = 0;
			FILTERCF(InjPushLibInfo(*libinfoNew, interp, verbose) != RESCODE_SUCCESS, verbose, break);
		}
		FILTERCF(InjSortSymbols(*symtabNew, FALSE, TRUE, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjSortSymbols(*symtabNew, TRUE, TRUE, verbose) != RESCODE_SUCCESS, verbose, break);
		*elfNew = elf;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(elf != NULL) free(elf);
		if(interp != NULL){
			free(interp->libname);
			free(interp);
		}
	}
	return res;
}
//load elf header information we interest in,
API_PRIVATE ResCode InjLoadElfHdr(ElfHdr *ehdr, int fd, int verbose){
	int res = RESCODE_FAIL;
	if(ehdr == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, ehdr, fd);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		Elf_Ehdr elf;
		errno = 0;
		memset(ehdr, 0, sizeof(*ehdr));
		FILTERC(lseek(fd, 0, SEEK_SET) < 0, verbose, RESCODE_FAIL_SEEK, break);
		FILTERC(read(fd, &elf, sizeof(Elf_Ehdr)) < 0, verbose, RESCODE_FAIL_READ, break);
		//"0X7FELF"
		if(elf.e_ident[EI_MAG0] != 0x7F || elf.e_ident[EI_MAG1] != 'E' ||
				elf.e_ident[EI_MAG2] != 'L' || elf.e_ident[EI_MAG3] != 'F'){
			LOG(ERROR "no ELF file\n"); break;
		}
		//object's class
		if(elf.e_ident[EI_CLASS] == ELFCLASS32) ehdr->bits = CPUBITS_32;
		else if(elf.e_ident[EI_CLASS] == ELFCLASS64) ehdr->bits = CPUBITS_64;
		else{ LOG(ERROR "invalid cpu bits, options: 32-bit | 64-bit\n"); break; }
		//endian
		if(elf.e_ident[EI_DATA] == ELFDATA2LSB) ehdr->endian = ENDIAN_LITTLE;
		else if(elf.e_ident[EI_DATA] == ELFDATA2MSB) ehdr->endian = ENDIAN_BIG;
		else{ LOG(ERROR "invalid endian, options: little | big\n"); break; }
		//file type
		ehdr->ftype = InjGetFileType(elf.e_type);
		if(elf.e_machine != EM_386 && elf.e_machine != EM_X86_64){
			LOG(ERROR "architecture not support, options: X86-32 | X86-64\n"); break;
		}
		ehdr->entry = elf.e_entry;
		if(elf.e_phoff > 0){
			ehdr->phoff = elf.e_phoff;
			ehdr->phunitsz = elf.e_phentsize;
			ehdr->phnum = elf.e_phnum;
		}
		if(elf.e_shoff > 0){
			ehdr->shoff = elf.e_shoff;
			ehdr->shunitsz = elf.e_shentsize;
			ehdr->shnum = elf.e_shnum;
		}
		ehdr->shstrind = elf.e_shstrndx;
		res = RESCODE_SUCCESS;
	}while(0);
	return res;
}
//convert system filetype to local filetype
API_PRIVATE FileType InjGetFileType(int e_type){
	if(e_type == ET_REL) return FILETYPE_REL;
	if(e_type == ET_EXEC) return FILETYPE_EXEC;
	if(e_type == ET_DYN) return FILETYPE_SO;
	if(e_type == ET_CORE) return FILETYPE_CORE;
	return FILETYPE_INVALID;
}
//load section header information we interest in,
///InjLoadSymTab
API_PRIVATE ResCode InjLoadSecHdr(SecHdr **shdrNew, Symbol **symtabNew, ElfInfo *elfinfo, int fd, int verbose){
	int res = RESCODE_FAIL;
	SecHdr *this = NULL;
	Elf_Shdr *shtab = NULL;
	char *strbuf = NULL;
	if(shdrNew == NULL || symtabNew == NULL || elfinfo == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, shdrNew, symtabNew);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	*shdrNew = NULL;
	do{
		int i;
		char symtabexist = 0;
		ElfHdr *ehdr = &elfinfo->elf;
		size_t secsz = ehdr->shnum * ehdr->shunitsz;
		errno = 0;
		FILTERC((shtab = malloc(secsz)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC(lseek(fd, ehdr->shoff, SEEK_SET) == -1, verbose, RESCODE_FAIL_SEEK, break);
		FILTERC(read(fd, shtab, secsz) == -1, verbose, RESCODE_FAIL_READ, break);
		Elf_Shdr *strsh = &shtab[ehdr->shstrind];
		FILTERC((strbuf = malloc(strsh->sh_size)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC(lseek(fd, strsh->sh_offset, SEEK_SET) == -1, verbose, RESCODE_FAIL_SEEK, break);
		FILTERC(read(fd, strbuf, strsh->sh_size) == -1, verbose, RESCODE_FAIL_READ, break);
		int symtabind = 0, dynsymind = 0;
		//sechdr[0] is not used, only zero in it
		for(i = 1; i < (int)ehdr->shnum; ++i) if(shtab[i].sh_type == SHT_SYMTAB){ symtabexist = 1; break; } 
		FILTERC((this = malloc(sizeof(SecHdr) * ehdr->shnum)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memset(this, 0, sizeof(SecHdr) * ehdr->shnum);
		for(i = 1; i < (int)ehdr->shnum; ++i){
			char *shname = &strbuf[shtab[i].sh_name];
			if(verbose >= LOGLEVEL_DEBUG)
				LOG(DEBUG "found [%s], offset[%#lx], size[%#lx]\n", shname, shtab[i].sh_offset, shtab[i].sh_size);
			switch(shtab[i].sh_type){
				case SHT_SYMTAB:
					symtabind = i; break;
				case SHT_DYNSYM:
					dynsymind = i; break;
				case SHT_STRTAB:
					if(symtabexist){
						if(symtabind){
							FILTERCF(InjLoadSymTab(symtabNew, &shtab[symtabind], &shtab[i], fd, verbose), verbose, goto out);
							symtabind = 0;
						}
					}
					else{
						if(dynsymind){
							FILTERCF(InjLoadSymTab(symtabNew, &shtab[dynsymind], &shtab[i], fd, verbose), verbose, goto out);
							dynsymind = 0;
						}
					}
					break;
				default: break;
			}
			this[i].nmind = shtab[i].sh_name;
			this[i].offset = shtab[i].sh_offset;
			if(shtab[i].sh_flags & SHF_WRITE) this[i].perm |= PERMISSION_WR;
			if(shtab[i].sh_flags & SHF_EXECINSTR) this[i].perm |= PERMISSION_EXEC;
			if(shtab[i].sh_flags & SHF_ALLOC) this[i].perm |= PERMISSION_ALLOC;
			this[i].stype = shtab[i].sh_type;
			this[i].tbitemsz = shtab[i].sh_entsize;
			this[i].tbzonesz = shtab[i].sh_size;
		}
		elfinfo->shnum = ehdr->shnum;
		*shdrNew = this;
		free(shtab);
		free(strbuf);
		shtab = NULL;
		strbuf = NULL;
		res = RESCODE_SUCCESS;
	}while(0);
out:
	if(res != RESCODE_SUCCESS){
		if(shtab != NULL) free(shtab);
		if(strbuf != NULL) free(strbuf);
		if(this != NULL) free(this);
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Exit %s\n", __func__);
	return res;
}
//load symbol table according section header,
///InjGetSymTypeFromInfo
API_PRIVATE ResCode InjLoadSymTab(Symbol **symtabNew, Elf_Shdr *symtab, Elf_Shdr *strsh, int fd, int verbose){
	int res = RESCODE_FAIL;
	Symbol *this = NULL;
	Elf_Sym *symbuf = NULL;
	char *strbuf = NULL;
	if(symtabNew == NULL || symtab == NULL || strsh == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, symtabNew, symtab, verbose);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	*symtabNew = NULL;
	do{
		if(symtab->sh_size <= 0 || symtab->sh_entsize <= 0){
			LOG(ERROR "requre symbol table but there isn't any\n");
			break;
		}
		size_t symnum = symtab->sh_size/symtab->sh_entsize;
		FILTERC((this = malloc(sizeof(Symbol))) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memset(this, 0, sizeof(Symbol));
		FILTERC((this->syms = malloc(sizeof(SymNode) * symnum)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC((this->sortaddr = malloc(sizeof(int) * symnum)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC((this->sortname = malloc(sizeof(int) * symnum)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);

		FILTERC((symbuf = malloc(symtab->sh_size)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC(lseek(fd, symtab->sh_offset, SEEK_SET) < 0, verbose, RESCODE_FAIL_SEEK, break);
		FILTERC(read(fd, symbuf, symtab->sh_size) < 0, verbose, RESCODE_FAIL_READ, break);

		FILTERC((strbuf = malloc(strsh->sh_size)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC(lseek(fd, strsh->sh_offset, SEEK_SET) < 0, verbose, RESCODE_FAIL_SEEK, break);
		FILTERC(read(fd, strbuf, strsh->sh_size) < 0, verbose, RESCODE_FAIL_SEEK, break);

		SymNode *nodes = this->syms;
		unsigned int *sorta = this->sortaddr;
		unsigned int *sortn = this->sortname;
		memset(nodes, 0, sizeof(SymNode) * symnum);
		memset(sorta, 0, sizeof(int) * symnum);
		memset(sortn, 0, sizeof(int) * symnum);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "%d symbols in total\n", (int)symnum);
		for(size_t i = 0; i < symnum; ++i){
			const char *name = symbuf[i].st_name > 0 ? &strbuf[symbuf[i].st_name] : "";
			sorta[i] = sortn[i] = i;
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "[%s] at %#lx, size %ld\n", name, symbuf[i].st_value, symbuf[i].st_size);
			FILTERC((nodes[i].name = strdup(name)) == NULL, verbose, RESCODE_FAIL_ALLOC, goto out);
			nodes[i].type = InjGetSymTypeFromInfo(symbuf[i].st_info);
			nodes[i].addr = symbuf[i].st_value;
			nodes[i].sz = symbuf[i].st_size;
		}
		free(strbuf), strbuf = NULL;
		free(symbuf), symbuf = NULL;
		this->num = symnum;
		*symtabNew = this;
		res = RESCODE_SUCCESS;
	}while(0);
out:
	if(res != RESCODE_SUCCESS){
		if(strbuf != NULL) free(strbuf);
		if(symbuf != NULL) free(symbuf);
		if(this != NULL){
			SymNode *nodes = this->syms;
			if(this->syms){
				for(size_t i = 0; i < this->num; ++i) free(nodes->name);
				free(this->syms);
			}
			if(this->sortaddr) free(this->sortaddr);
			if(this->sortname) free(this->sortname);
			free(this);
		}
	}
	return res;
}
//retrieve type of symbol,
API_PRIVATE SymType InjGetSymTypeFromInfo(unsigned char info){
	switch(ELF64_ST_TYPE(info)){
		case STT_NOTYPE: return SYMTYPE_INVALID;
		case STT_OBJECT: return SYMTYPE_OBJ;
		case STT_FUNC: return SYMTYPE_FUNC;
		case STT_FILE: return SYMTYPE_FILE;
		case STT_SECTION: return SYMTYPE_SEC;
		default: break;
	}
	return SYMTYPE_INVALID;
}
//load program header information we interest in,
API_PRIVATE ResCode InjLoadProHdr(ProgHdr **phdrNew, unsigned int*phdrnum, ElfHdr *ehdr, int fd, int verbose){
	ResCode res = RESCODE_FAIL;
	ProgHdr *this = NULL;
	Elf_Phdr *phbuf = NULL;
	if(phdrNew == NULL || phdrnum == NULL || ehdr == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, phdrNew, phdrnum);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	*phdrNew = NULL;
	*phdrnum = 0;
	do{
		int j = 0;
		int phsz = ehdr->phnum * ehdr->phunitsz;
		FILTERC((phbuf = malloc(phsz)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC(lseek(fd, ehdr->phoff, SEEK_SET) < 0, verbose, RESCODE_FAIL_SEEK, break);
		FILTERC(read(fd, phbuf, phsz) < 0, verbose, RESCODE_FAIL_READ, break);

		FILTERC((this = malloc(sizeof(ProgHdr) * 2)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memset(this, 0, sizeof(ProgHdr) * 2);
		for(size_t i = 0; i < ehdr->phnum; ++i){
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "found program header, type[%d], "
					"offset[%#lx], vaddr[%#lx], paddr[%#lx], filesize[%ld], memsize[%ld]\n",
					phbuf[i].p_type,
					phbuf[i].p_offset, phbuf[i].p_vaddr, phbuf[i].p_paddr, phbuf[i].p_filesz, phbuf[i].p_memsz);
			if(phbuf[i].p_type == PT_INTERP && ehdr->ftype == FILETYPE_EXEC){
				if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "found INTERP, load it\n");
				FILTERC((this[j].name.addr = malloc(phbuf[i].p_filesz)) == NULL, verbose, RESCODE_FAIL_ALLOC, goto out);
				FILTERC(lseek(fd, phbuf[i].p_offset, SEEK_SET) < 0, verbose, RESCODE_FAIL_SEEK, goto out);
				FILTERC(read(fd, this[j].name.addr, phbuf[i].p_filesz) < 0, verbose, RESCODE_FAIL_READ, goto out);
				this[j].name.len = phbuf[i].p_filesz;
				this[j].offset = phbuf[i].p_offset;
				if(phbuf[i].p_flags & PF_R) this[j].perm |= PERMISSION_RD;
				if(phbuf[i].p_flags & PF_W) this[j].perm |= PERMISSION_WR;
				if(phbuf[i].p_flags & PF_X) this[j].perm |= PERMISSION_EXEC;
				this[j].ptype = PT_INTERP;
				this[j].vaddr = phbuf[i].p_vaddr;
				++j;
			}
			else if(phbuf[i].p_type == PT_DYNAMIC){
				if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "found _DYNAMIC, load it\n");
				if(phbuf[i].p_flags & PF_R) this[j].perm |= PERMISSION_RD;
				if(phbuf[i].p_flags & PF_W) this[j].perm |= PERMISSION_WR;
				if(phbuf[i].p_flags & PF_X) this[j].perm |= PERMISSION_EXEC;
				this[j].ptype = PT_DYNAMIC;
				this[j].vaddr = phbuf[i].p_vaddr;
				++j;
			}
		}
		*phdrnum = j;
		*phdrNew = this;
		free(phbuf), phbuf = NULL;
		res = RESCODE_SUCCESS;
	}while(0);
out:
	if(res != RESCODE_SUCCESS){
		if(phbuf != NULL) free(phbuf);
		if(this != NULL){
			for(int i = 0; i < 2; ++i) if(this[i].name.addr) free(this[i].name.addr);
			free(this);
		}
	}
	return res;
}
//scan maps of target process to get dependent libraries,
///InjParseMapsEntry
API_PRIVATE ResCode InjScanMaps(LibInfo **libsNew, pid_t pid, int verbose){
#define MAPENTRY_SZ 128
	ResCode res = RESCODE_FAIL;
	LibInfo *this = NULL;
	char mapfile[EXENAME_LEN];
	FILE *fp = NULL;
	if(libsNew == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, libsNew, NULL);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	*libsNew = NULL;
	do{
		FILTERC((this = malloc(sizeof(*this))) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memset(this, 0, sizeof(*this));
		FILTERCF(snprintf(mapfile, EXENAME_LEN, "/proc/%d/maps", pid) <= 0, verbose, break);
		FILTERC((fp = fopen(mapfile, "rt")) == NULL, verbose, RESCODE_FAIL_OPEN, break);
		char entrybuf[MAPENTRY_SZ] = { 0 };
		LibNodes *nodes = NULL, *prev = NULL;
		int i = 0;
		while(fgets(entrybuf, sizeof(entrybuf), fp) != NULL){
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "entry[%d]: %s", i, entrybuf);
			FILTERCF(InjParseMapsEntry(&nodes, entrybuf, pid, verbose) != RESCODE_SUCCESS, verbose,  goto out);
			if(prev != NULL) prev->next = nodes;
			else this->nodes = nodes;
			nodes->prev = prev;
			prev = nodes;
			++i;
		}
		prev->next = NULL;
		fclose(fp), fp = NULL;
		if(verbose >= LOGLEVEL_DEBUG){
			LOG(DEBUG "addr                permission  inode    next       prev      type   name\n");
			for(nodes = this->nodes; nodes != NULL; nodes = nodes->next)
				LOG(DEBUG "%#-20lx  %-8x  %-6ld  %-8p  %-10p  %-4d  %s\n", nodes->bgnaddr, nodes->perm, nodes->inode, 
						nodes->next, nodes->prev, nodes->type, nodes->libname ? nodes->libname : "");
		}
		this->num = i;
		*libsNew = this;
		res = RESCODE_SUCCESS;
	}while(0);
out:
	if(res != RESCODE_SUCCESS){
		if(fp != NULL) fclose(fp);
		InjClearbInfo(&this);
	}
	return res;
}

//list node insert to front -- list[0]
API_PRIVATE ResCode InjPushLibInfo(LibInfo *libinfo, LibNodes *elem, int verbose){
	if(libinfo == NULL || elem == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, libinfo, elem);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	LibNodes *this = libinfo->nodes;
	elem->next = this;
	this->prev = elem;
	elem->prev = NULL;
	libinfo->nodes = elem;
	++libinfo->num;
	return RESCODE_SUCCESS;
}
//destory linked list
API_PRIVATE void InjClearbInfo(LibInfo **libinfo){
	if(libinfo == NULL) return;
	LibNodes *cur = (*libinfo)->nodes, *next;
	if(cur){
		while(cur != NULL){
			next = cur->next;
			free(cur);
			cur = next;
		}
	}
	free(*libinfo);
	*libinfo = NULL;
}

//parse each line of mapsv,
API_PRIVATE ResCode InjParseMapsEntry(LibNodes **libnodeNew, char *entry, pid_t pid, int verbose){
	//to split each part of one line with strtok_r(), contains: bgn addr, permission, offset, device, inode, path, entry type
	ResCode res = RESCODE_FAIL;
	LibNodes *this = NULL;
	if(libnodeNew == NULL || entry == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, libnodeNew, entry);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	*libnodeNew = NULL;
	do{
		char *last = NULL, *tok = NULL;
		errno = 0;
		FILTERC((this = malloc(sizeof(LibNodes))) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memset(this, 0, sizeof(LibNodes));
		FILTERC((tok = strtok_r(entry, dash, &last)) == NULL, verbose, RESCODE_FAIL, break);
		this->bgnaddr = strtoul(tok, NULL, 16);
		FILTERC(errno == ERANGE, verbose, RESCODE_FAIL_NODIGIT, break);
		FILTERC((tok = strtok_r(NULL, sp, &last)) == NULL, verbose, RESCODE_FAIL, break); //now, tok = last address
		this->endaddr = strtoul(tok, NULL, 16);
		FILTERC((tok = strtok_r(NULL, sp, &last)) == NULL, verbose, RESCODE_FAIL, break); //now, tok = permission
		for(int i = strlen(tok)-1; i >= 0; --i){
			if(tok[i] == 'p') this->perm |= PERMISSION_PRIVATE;
			else if(tok[i] == 's') this->perm |= PERMISSION_SHARED;
			else if(tok[i] == 'x') this->perm |= PERMISSION_EXEC;
			else if(tok[i] == 'w') this->perm |= PERMISSION_WR;
			else if(tok[i] == 'r') this->perm |= PERMISSION_RD;
		}
		FILTERC((tok = strtok_r(NULL, colon, &last)) == NULL, verbose, RESCODE_FAIL, break); //skip offset, tok = major
		FILTERC((tok = strtok_r(NULL, sp, &last)) == NULL, verbose, RESCODE_FAIL, break); //skip minus device, tok = minus
		FILTERC((tok = strtok_r(NULL, sp, &last)) == NULL, verbose, RESCODE_FAIL, break); //now, tok = inode
		this->inode = (ino_t)strtoul(tok, NULL, 10);
		FILTERC(errno == ERANGE, verbose, RESCODE_FAIL_NODIGIT, break);
		/* there may be '\n' only in last, for example:
		 * 7f53bbe0c000-7f53bbe2d000 r-xp 00000000 fd:00 917584                     /lib64/ld-2.15.so
		 * 7f53bc01d000-7f53bc020000 rw-p 00000000 00:00 0
		 * thus, I assume it an anonymous entry
		 * */
		if((tok = strtok_r(NULL, newline, &last)) == NULL){
			this->type = MAPTYPE_ANONY;
		   	goto anony_handle;
		} 
		//now, tok = name|absolute path-name
		if((last = strchr(tok, '/')) != NULL){
			tok = last;
			FILTERC((this->libname = calloc(1, strlen(tok) + 1)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
			memcpy(this->libname, tok, strlen(tok));
			if(strstr(tok, ".so") != NULL || strstr(tok, ".so.") != NULL) this->type = MAPTYPE_SO;
			else{
				struct stat statbuf;
				memset(&statbuf, 0, sizeof(statbuf));
				this->type = MAPTYPE_DATA;
				FILTERC(stat(this->libname, &statbuf) < 0, verbose, RESCODE_FAIL, break);
				ino_t inode = statbuf.st_ino;
				char selfexe[EXENAME_LEN] = { 0 };
				FILTERC(snprintf(selfexe, EXENAME_LEN, "/proc/%d/exe", pid) < 0, verbose, RESCODE_FAIL, break);
				FILTERC(stat(selfexe, &statbuf) < 0, verbose, RESCODE_FAIL, break);
				if(inode == statbuf.st_ino) this->type = MAPTYPE_EXE;
			}
		}
		else if((last = strchr(tok, '[')) != NULL){
			tok = last;
			FILTERC((this->libname = calloc(1, strlen(tok) + 1)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
			memcpy(this->libname, tok, strlen(tok));
			if(strstr(tok, "[stack]") != NULL) this->type = MAPTYPE_STACK;
			else if(strstr(tok, "[heap]") != NULL) this->type = MAPTYPE_HEAP;
			else if(strstr(tok, "[vdso]") != NULL) this->type = MAPTYPE_VDSO;
			else if(strstr(tok, "[vsyscall]") != NULL) this->type = MAPTYPE_SYSCALL;
		}
		else{
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "invalid map type\n");
			this->type = MAPTYPE_INVALID;
		}
anony_handle:
		*libnodeNew = this;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(this != NULL){
			if(this->libname){
				free(this->libname);
				this->libname = (char*)0;
			}
			free(this);
		}
	}
	return res;
}

API_PRIVATE void SwapMem(void *a, void *b, int unit){
	if(a == b) return;
	char t;
	char *_a = (char *)a;
	char *_b = (char *)b;
	while(--unit >= 0){
		t = *_a;
		*_a = *_b;
		*_b = t;
		++_a, ++_b;
	}
}
API_PRIVATE char *median(void *s, int unit, int low, int hi,
		int (*compare)(const void *a, const void *b, ...),
		...){
	SymNode *syms = NULL;
	char *_s = (char *)s;
	int mid = low + (hi-low)/2;
	int _lo = low*unit, _mi = mid*unit, _hi = hi*unit;
	va_start(ap, compare);
	syms = va_arg(ap, SymNode*);
	va_end(ap);
	if(compare(_s + _mi, _s + _hi, syms) > 0) SwapMem(_s + _mi, _s + _hi, unit);
	if(compare(_s + _lo, _s + _hi, syms) > 0) SwapMem(_s + _lo, _s + _hi, unit);
	if(compare(_s + _mi, _s + _lo, syms) > 0) SwapMem(_s + _mi, _s + _lo, unit);
	return _s + _lo;
}
API_PRIVATE void SortInsertionShellNThread1(void *s, int unit, int ls, int re,
		int (*compare)(const void *a, const void *b, ...),
		...){
	SymNode *syms = NULL;
	int gap = re - ls + 1;
	char *_s = (char*)s;
	char pivot[unit];
	int i, j;
	va_start(ap, compare);
	syms = va_arg(ap, SymNode*);
	va_end(ap);
	do{
		gap = gap / 3 + 1;
		for(i = ls + gap; i <= re; ++i){
			memcpy(pivot, _s + i*unit, unit);
			for(j = i-gap; j >= ls && compare(pivot, _s + j*unit, syms) < 0; j -= gap)
				memcpy(_s + (j+gap)*unit, _s + j*unit, unit);
			memcpy(_s + (j+gap)*unit, pivot, unit);
		}
	}while(gap > 1);
}
API_PRIVATE void SortQuickMergeOpt_Re(void *s, int unit, int ls, int re, 
		int (*compare)(const void *a, const void *b, ...),
		...){
	if(ls >= re) return;
	if(re - ls + 1 < 10) SortInsertionShellNThread1(s, unit, ls, re, compare);
	SymNode *syms = NULL;
	int p, q, i, j;
	char *_s = (char *)s;
	char pivot[unit];
	int cmp;
	va_start(ap, compare);
	syms = va_arg(ap, SymNode*);
	va_end(ap);
	memcpy(pivot, median(s, unit,  ls, re, compare, syms), unit);
	i = p = ls*unit;
	j = q = re*unit;
	while(i < j){
		while(i < j && (cmp = compare(_s + j, pivot, syms)) >= 0){
			if(!cmp){
				SwapMem(_s + j, _s + q, unit);
				q -= unit;
			}
			j -= unit;
		}
		if(i - j) memcpy(_s + i, _s + j, unit);
		while(i < j && (cmp = compare(_s + i, pivot, syms)) <= 0){
			if(!cmp){
				SwapMem(_s + i, _s + p, unit);
				p += unit;
			}
			i += unit;
		}
		if(i - j) memcpy(_s + j, _s + i, unit);
	}
	memcpy(_s + i, pivot, unit);
	j += unit, q += unit;
	while(q <= re*unit && compare(_s + j, pivot, syms)){
		SwapMem(_s + j, _s + q, unit);
		j += unit, q += unit;
	}
	i -= unit, p -= unit;
	while(p >= ls*unit && compare(_s + i, pivot, syms)){
		SwapMem(_s + i, _s + p, unit);
		i -= unit, p -= unit;
	}
	SortQuickMergeOpt_Re(s, unit, ls, i/unit, compare, syms);
	SortQuickMergeOpt_Re(s, unit, j/unit, re, compare, syms);
}
//sort symbols by address or name, only support type 'int' re now
static int compAddr(const void *a, const void *b, ...){
	SymNode *syms;
	uintptr_t A, B;
	va_start(ap, b);
	syms = va_arg(ap, SymNode*);
	va_end(ap);
	A = syms[*(int*)a].addr, B = syms[*(int*)b].addr;
	return A > B ? 1 : A < B ? -1 : 0;
}
static int compName(const void *a, const void *b, ...){
	SymNode *syms;
	va_start(ap, b);
	syms = va_arg(ap, SymNode*);
	va_end(ap);
	return strcmp(syms[*(int*)a].name, syms[*(int*)b].name);
}
static int compAddrDes(const void *a, const void *b, ...){
	SymNode *syms;
	uintptr_t A, B;
	va_start(ap, b);
	syms = va_arg(ap, SymNode*);
	va_end(ap);
	A = syms[*(int*)a].addr, B = syms[*(int*)b].addr;
	return A < B ? 1 : A > B ? -1 : 0;
}
static int compNameDes(const void *a, const void *b, ...){
	SymNode *syms;
	va_start(ap, b);
	syms = va_arg(ap, SymNode*);
	va_end(ap);
	return strcmp(syms[*(int*)b].name, syms[*(int*)a].name);
}
API_PRIVATE ResCode InjSortSymbols(Symbol *symtab, char is_namebase, char is_acend, int verbose){
	ResCode res = RESCODE_FAIL;
	if(symtab == NULL || symtab->syms == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, symtab, symtab->syms);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		FILTERCF((unsigned)(symtab->num-1)*sizeof(int) > INT_MAX, verbose, LOG(ERROR "numeric overflow, too many symbols\n"); break);
		if(verbose >= LOGLEVEL_MORE){
			SymNode *nodes = symtab->syms;
			unsigned int *at;
			if(is_namebase){
				at = symtab->sortname;
				LOG(MORE "before sort by name, %d symbols\n", symtab->num);
				for(int i = 0; i < (int)symtab->num; ++i) LOG(MORE "#%d: %u %s\n", i, at[i], nodes[at[i]].name);
			}
			else{
				at = symtab->sortaddr;
				LOG(MORE "before sort by addr, %d symbols\n", symtab->num);
				for(int i = 0; i < (int)symtab->num; ++i) LOG(MORE "#%d: %u %#lx\n", i, at[i], nodes[at[i]].addr);
			}
		}
		if(is_acend){
			if(is_namebase) SortQuickMergeOpt_Re(symtab->sortname, sizeof(int), 0, symtab->num - 1, compName, symtab->syms);
			else SortQuickMergeOpt_Re(symtab->sortaddr, sizeof(int), 0, symtab->num - 1, compAddr, symtab->syms);
		}
		else{
			if(is_namebase) SortQuickMergeOpt_Re(symtab->sortname, sizeof(int), 0, symtab->num - 1, compNameDes, symtab->syms);
			else SortQuickMergeOpt_Re(symtab->sortaddr, sizeof(int), 0, symtab->num - 1, compAddrDes, symtab->syms);
		}
		if(verbose >= LOGLEVEL_MORE){
			SymNode *nodes = symtab->syms;
			unsigned int *at;
			if(is_namebase){
				at = symtab->sortname;
				LOG(MORE "after sort by name, %d symbols\n", symtab->num);
				for(int i = 0; i < (int)symtab->num; ++i) LOG(MORE "#%d: %u %s\n", i, at[i], nodes[at[i]].name);
			}
			else{
				at = symtab->sortaddr;
				LOG(MORE "after sort by addr, %d symbols\n", symtab->num);
				for(int i = 0; i < (int)symtab->num; ++i) LOG(DEBUG "#%d: %u %#lx\n", i, at[i], nodes[at[i]].addr);
			}
		}
		res = RESCODE_SUCCESS;
	}while(0);
	return res;
}
//merge symbols,
API_PRIVATE ResCode InjMergeSymbols(Symbol **out, Symbol *symtab1, Symbol *symtab2, int verbose){
	ResCode res = RESCODE_FAIL;
	size_t n1, n2;
	size_t total;
	Symbol *this = NULL;
	if(out == NULL || symtab1 == NULL || symtab2 == NULL || !symtab1->num || !symtab2->num){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, symtab1, symtab2);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		n1 = symtab1->num, n2 = symtab2->num;
		total = n1 + n2;
		FILTERC((this = malloc(sizeof(Symbol))) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memset(this, 0, sizeof(Symbol));
		FILTERC((this->syms = malloc(sizeof(SymNode) * total)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC((this->sortaddr = malloc(sizeof(int) * total)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC((this->sortname = malloc(sizeof(int) * total)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memcpy(this->syms, symtab1->syms, symtab1->num * sizeof(SymNode));
		memcpy(this->syms + n1*sizeof(SymNode), symtab2->syms, n2*sizeof(SymNode));
		this->num = total;
		for(size_t i = 0; i < total; ++i){
			this->sortaddr[i] = this->sortname[i] = i;
		}
		FILTERCF(InjSortSymbols(this, FALSE, TRUE, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjSortSymbols(this, TRUE, TRUE, verbose) != RESCODE_SUCCESS, verbose, break);
		*out = this;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(this != NULL){
			if(this->syms) free(this->syms);
			if(this->sortaddr) free(this->sortaddr);
			if(this->sortname) free(this->sortname);
			free(this);
		}
	}
	return RESCODE_SUCCESS;
}
//validate target address valid or not
API_PRIVATE ResCode InjTgtAddrValidate(const LibInfo *libinfo, uintptr_t tgtaddr, int len, int verbose){
	LibNodes *nodes;
	if(libinfo == NULL || tgtaddr == 0){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, libinfo, tgtaddr);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	nodes = libinfo->nodes;
	while(nodes != NULL){
		if(nodes->bgnaddr){
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "validate address in %s\n", nodes->libname);
			if(!len){
				if(nodes->bgnaddr <= tgtaddr && nodes->endaddr >= tgtaddr) return RESCODE_SUCCESS;
			}
			else{
				if(nodes->bgnaddr <= tgtaddr && nodes->endaddr >= tgtaddr
						&& nodes->bgnaddr <= tgtaddr+len && nodes->endaddr >= tgtaddr+len)
					return RESCODE_SUCCESS;
			}
		}
		nodes = nodes->next;
	}
	return RESCODE_FAIL;
}
//find syscall/C-funcs we need,
///InjOpenFile
///InjLoadElf
///InjFindSymByName
API_PRIVATE ResCode InjGetSysFuncFromMapsLibs(SysFunc *sysfnNew, LibInfo *libinfo, pid_t pid, int verbose){
	ResCode res = RESCODE_FAIL;
	int fd = -1;
	LibNodes *tgt = NULL;
	ElfInfo *dumpelf = NULL;
	Symbol *symtab = NULL;
	LibInfo *dumplibinfo = NULL;
	SysFunc *this = sysfnNew;
	if(sysfnNew == NULL || libinfo == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, sysfnNew, libinfo);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
#define SYSFUNST_SZ (int)(sizeof(SysFunc)/sizeof(uintptr_t))
		LibNodes *libs = libinfo->nodes;
		char *syslibs[2] = { INJ_LIB_C, INJ_LIB_LD };
		memset(this, 0, sizeof(SysFunc));
		for(int i = 0; i < (int)(sizeof(syslibs)/sizeof(syslibs[0])); ++i){
			FILTERCF(InjFindLib(&tgt, libs, syslibs[i], verbose) != RESCODE_SUCCESS, verbose, continue);
			FILTERCF(InjOpenFile(&fd, tgt->libname, verbose) != RESCODE_SUCCESS, verbose, goto out);
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "loading symbols from [%s]\n", tgt->libname);
			FILTERCF(InjLoadElf(&dumpelf, &dumplibinfo, &symtab, fd, pid, verbose) != RESCODE_SUCCESS, verbose, goto out);
			close(fd), fd = -1;
			if(this->alloc == 0){
				if((this->alloc = InjFindSymByName(INJ_C_LD_MALLOC, symtab, verbose))) this->alloc += tgt->bgnaddr;
			}
			if(this->free == 0){
				if((this->free = InjFindSymByName(INJ_C_LD_FREE, symtab, verbose))) this->free += tgt->bgnaddr;
			} 
			if(this->strlen == 0){
				if((this->strlen = InjFindSymByName(INJ_C_STRLEN, symtab, verbose))) this->strlen += tgt->bgnaddr;
			} 
			if(this->printf == 0){
				if((this->printf = InjFindSymByName(INJ_C_LD_PRINTF, symtab, verbose))) this->printf += tgt->bgnaddr;
			}
			if(this->fopen == 0){
				if((this->fopen = InjFindSymByName(INJ_C_LD_FOPEN, symtab, verbose))) this->fopen += tgt->bgnaddr;
			} 
			if(this->fprintf == 0){
				if((this->fprintf = InjFindSymByName(INJ_C_LD_FPRINTF, symtab, verbose))) this->fprintf += tgt->bgnaddr;
			} 
			if(this->fclose == 0){
				if((this->fclose = InjFindSymByName(INJ_C_LD_FCLOSE, symtab, verbose))) this->fclose += tgt->bgnaddr;
			} 
			if(this->system == 0){
				if((this->system = InjFindSymByName(INJ_C_SYSTEM, symtab, verbose))) this->system += tgt->bgnaddr;
			} 
			if(this->dlopen == 0){
				if((this->dlopen = InjFindSymByName(INJ_C_DLOPEN, symtab, verbose))) this->dlopen += tgt->bgnaddr;
			} 
			if(this->dlsym == 0){
				if((this->dlsym = InjFindSymByName(INJ_C_DLSYM, symtab, verbose))) this->dlsym += tgt->bgnaddr;
			} 
			if(this->dlclose == 0){
				if((this->dlclose = InjFindSymByName(INJ_C_DLCLOSE, symtab, verbose))) this->dlclose += tgt->bgnaddr;
			} 
			FILTERCF(InjFreeElf(&dumpelf, &dumplibinfo, &symtab, verbose) != RESCODE_SUCCESS, verbose, goto out);
			//break in advance if we found all necessary functions in libc or libdl to optimize
			int sum = 0;
			for(int i = 0; i < SYSFUNST_SZ  - 1; ++i){
				if(*(&this->alloc + i)) ++sum;
			}
			if(sum == SYSFUNST_SZ - 1) goto done_in_advance;
		}
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "loading symbols from [%s]\n", INJ_LIB_DL);
		FILTERCF(InjFindLib(&tgt, libs, INJ_LIB_DL, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjOpenFile(&fd, tgt->libname, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLoadElf(&dumpelf, &dumplibinfo, &symtab, fd, pid, verbose) != RESCODE_SUCCESS, verbose, break);
		close(fd), fd = -1;
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "loading DL librarie symbols\n");
		if(this->dlopen == 0){
			if((this->dlopen = InjFindSymByName(INJ_DL_OPEN, symtab, verbose))) this->dlopen += tgt->bgnaddr;
		} 
		if(this->dlsym == 0){
			if((this->dlsym = InjFindSymByName(INJ_DL_SYM, symtab, verbose))) this->dlsym += tgt->bgnaddr;
		} 
		if(this->dlclose == 0){
			if((this->dlclose = InjFindSymByName(INJ_DL_CLOSE, symtab, verbose))) this->dlclose += tgt->bgnaddr;
		} 
		FILTERCF(InjFreeElf(&dumpelf, &dumplibinfo, &symtab, verbose) != RESCODE_SUCCESS, verbose, break);
		for(int i = 0; i < SYSFUNST_SZ - 1; ++i){
			if(*(&this->alloc + i) == 0){
				LOG(ERROR "can't find library functions at callset[%d]\n", i);
				goto out;
			}
		}
done_in_advance:
		this->isinit = 1;
		res = RESCODE_SUCCESS;
	}while(0);
out:
	if(res != RESCODE_SUCCESS){
		if(fd != -1) close(fd);
		InjFreeElf(&dumpelf, &dumplibinfo, &symtab, verbose);
	}
	return res;
}
//search so-lib by lib's name
API_PRIVATE ResCode InjFindLib(LibNodes **out, LibNodes *libs, char *libname, int verbose){
	if(out == NULL || libs == NULL || libname == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, out, libname);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	while(libs != NULL){
		if(libs->libname == NULL) goto next_lib;
		if(strstr(libs->libname, libname) != NULL){
			*out = libs;
			return RESCODE_SUCCESS;
		}
next_lib:
		libs = libs->next;
	}
	if(verbose >= LOGLEVEL_WARN) LOG(WARN "can't find lib [%s]\n", libname);
	return RESCODE_FAIL;
}
//search symbol address by name from symbol table
API_PRIVATE uintptr_t InjFindSymByName(char *symname, Symbol *symtab, int verbose){
	uintptr_t addr = 0;
	int lo = 0, hi = symtab->num;
	SymNode *syms = symtab->syms;
	unsigned int *sortn = symtab->sortname;
	int len = strlen(symname);
	char buf[len + 2];
	sprintf(buf, "%s@", symname);
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "searching symbol [%s]\n", symname);
	while(hi >= lo){
		int mi = lo + (hi - lo)/2;
		int cmp = strcmp(syms[sortn[mi]].name, symname);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "cur symbol is[%s]\n", syms[sortn[mi]].name);
		if(!cmp){
found_out:
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "found[%s] at %#lx\n", syms[sortn[mi]].name, syms[sortn[mi]].addr);
			return syms[sortn[mi]].addr;
		}
		else{//for some symbol like 'fopen' may be composed as 'fopen@@GLIBC...'
			if(cmp > 0){
				if(!strncmp(buf, syms[sortn[mi]].name, len+1)) goto found_out;
				hi = mi - 1;
			}
			else{
				if(!strncmp(buf, syms[sortn[mi]].name, len+1)) goto found_out;
				lo = mi + 1;
			}
		}
	}
	if(verbose >= LOGLEVEL_WARN) LOG(WARN "can't find symbol [%s]\n", symname);
	return addr;
}
//search symbol name by address from symbol table
API_PRIVATE const SymNode* InjFindSymByAddr(uintptr_t addr, Symbol *symtab, int verbose){
	SymNode *ret = NULL;
	int lo = 0, hi = symtab->num-1;
	SymNode *syms = symtab->syms;
	unsigned int *sorta = symtab->sortaddr;
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "searching symbol at [%#lx]\n", addr);
	while(hi >= lo){
		int mi = lo + (hi - lo)/2;
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "cur symbol is[%s]\n", syms[sorta[mi]].name);
		if(addr >= syms[sorta[mi]].addr && addr <= syms[sorta[mi]].addr+syms[sorta[mi]].sz){
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "found[%s] at %#lx\n", syms[sorta[mi]].name, syms[sorta[mi]].addr);
			return syms + sorta[mi];
		}
		else if(addr > syms[sorta[mi]].addr) lo = mi + 1;
		else hi = mi - 1;
	}
	if(verbose >= LOGLEVEL_WARN) LOG(WARN "no symbol at [%#lx]\n", addr);
	return ret;
}
//allocate memory in target process,
//InjLi*
API_PRIVATE ResCode InjGetTargetMemBlk(AuxStrs *auxNew, SysFunc *sys, pid_t pid, int verbose){
	ResCode res = RESCODE_FAIL;
	char isattach = 0;
	uintptr_t ret = 0;
	if(auxNew == NULL || sys == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, auxNew, sys);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		int i;
		AuxStrs *this = auxNew;
		int allocsz = TARGET_SIZEPERBLK*(TARGET_STRS_NUM+TARGET_MEMBLOCK_NUM);
		memset(this, 0, sizeof(*this));
		FILTERCF(InjLiAttach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 1;
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "call malloc[%#lx](%d)\n", sys->alloc, allocsz);
		FILTERCF(InjLiCall(&ret, verbose, pid, sys->alloc, sys, allocsz) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiDetach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 0;
		FILTERCF(ret == 0, verbose, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "return address of malloc is [%#lx]\n", ret);
		this->strnum = 0;
		this->blknum = 0;
		this->szperblk = TARGET_SIZEPERBLK;
		for(i = 0; i < TARGET_STRS_NUM; ++i) this->strs[i] = (char*)(ret + i*TARGET_SIZEPERBLK);
		for(; i < TARGET_STRS_NUM+TARGET_MEMBLOCK_NUM; ++i) this->memblk[i - TARGET_STRS_NUM] = ret + i*TARGET_SIZEPERBLK;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(isattach) InjLiDetach(pid, verbose);
		if(ret != -1UL) InjFreeTargetMemBlk(auxNew, sys, pid, verbose);
	}
	return res;
}
//free memory in target process,
API_PRIVATE ResCode InjFreeTargetMemBlk(AuxStrs *aux, SysFunc *sys, pid_t pid, int verbose){
	ResCode res = RESCODE_FAIL;
	char isattach = 0;
	if(aux == NULL || sys == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, aux, sys);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		FILTERCF(!sys->isinit, verbose, break);
		FILTERCF(InjLiAttach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 1;
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		//free as a whole block as allocated with a whole block before
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "call free[%#lx](%p)\n", sys->free, aux->strs[0]);
		if(aux->strs[0]) FILTERCF(InjLiCall(NULL, verbose, pid, sys->free, sys, aux->strs[0]) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLiDetach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 0;
		aux->blknum = 0;
		aux->strnum = 0;
		aux->szperblk = 0;
		memset(aux->strs, 0, sizeof(aux->strs));
		memset(aux->memblk, 0, sizeof(aux->memblk));
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(isattach) InjLiDetach(pid, verbose);
	}
	return res;
}
//generate asm code,
///InjGenAsmJump
///InjGenAsmSftIntr
API_PRIVATE ResCode InjGenerateAsmCmd(AsmCmd *asmcmdNew, int cmdtype, void *addr, void *data, int verbose){
	ResCode res = RESCODE_FAIL;
	AsmCmd *this = asmcmdNew;
	String *asmstr = NULL;
	if(asmcmdNew == NULL || cmdtype >= ASMCMD_BUT || cmdtype <= ASMCMD_INVALID){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, asmcmdNew, cmdtype);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		if(!this->num) memset(this, 0, sizeof(*this));
		switch(cmdtype){
			case ASMCMD_SFTINTR:
				asmstr = &asmcmdNew->sftintr;
				FILTERCF(InjGenAsmSftIntr(asmstr, cmdtype, verbose) != RESCODE_SUCCESS, verbose, goto out);
				++this->num;
				break;
			case ASMCMD_JUMP:
				asmstr = &asmcmdNew->jump;
				FILTERCF(InjGenAsmJump(asmstr, (uintptr_t)addr, cmdtype, verbose) != RESCODE_SUCCESS, verbose, goto out);
				++this->num;
				break;
			default: LOG(ERROR "invalid asm instruction\n"); goto out;
		}
		res = RESCODE_SUCCESS; //to keep model layout of each function, so keep it
	}while(0);
	(void)data;
out:
	return res;
}
//generate soft interrupt,
///InjCallShellCmd
#define ASM_BIT64(fp) {	\
	fputs("BITS 64\n", fp);	\
}
#define FUNC_PREFACE(fp) {	\
	fputs("push rbp\n", fp);	\
	fputs("mov rbp,rsp\n", fp);\
}
API_PRIVATE ResCode InjGenAsmCom(String *out, void *data, char *asmfile, char *args, char *objname, AsmCmdType type, int verbose){
	ResCode res = RESCODE_FAIL;
	FILE *fp = NULL;
	int fd = -1;
	size_t filesz = 0;
	char *cwd = NULL;
	char *asmdir = "ASM";
	char *abs_asmfile = NULL;
	char *absasmdir = NULL;
	char abspath[MAX_ARGUMENTLEN] = { 0 };
	if(out == NULL || asmfile == NULL || objname == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, out, asmfile);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		errno = 0;
		//make director 'absasmdir' ==> '${pwd}/ASM'
		FILTERC((cwd = getcwd(abspath, sizeof(abspath))) == NULL, verbose, RESCODE_FAIL, break);
		cwd[strlen(cwd)] = '/';
		FILTERC((absasmdir = strcat(abspath, asmdir)) == NULL, verbose, RESCODE_FAIL, break);
		FILTERC(mkdir(absasmdir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) && errno != EEXIST, verbose, RESCODE_FAIL_MKDIR, break);

		//make function preface with assembly codes in 'abs_asmfile' ==> '${pwd}/ASM/${asmfile}'
		absasmdir[strlen(absasmdir)] = '/';
		FILTERC((abs_asmfile = strcat(absasmdir, asmfile)) == NULL, verbose, RESCODE_FAIL, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "pushing function preface to [%s\n]", abs_asmfile);
		FILTERC((fp = fopen(abs_asmfile, "wt+")) == NULL, verbose, RESCODE_FAIL_OPEN, LOG(ERROR ">>>%s<<<\n", abs_asmfile); break);
		ASM_BIT64(fp);
		if(type != ASMCMD_JUMP) FUNC_PREFACE(fp);
		FILTERCF(fputs(data, fp) < 0, verbose, break);
		fclose(fp), fp = NULL;

		//generate relocable object file and read binary instruction
		*(strrchr(abs_asmfile, '/') + 1) = '\0'; // ==> '${pwd}/ASM/'
		fd = -1, filesz = 0;
		FILTERCF(InjCallShellCmd(SHELL_NASM, args, absasmdir, objname, &fd, &filesz, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERC((out->addr = malloc(filesz)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		FILTERC(read(fd, out->addr, filesz) < 0, verbose, RESCODE_FAIL_READ, break);
		close(fd), fd = -1;
		*strrchr(abs_asmfile, '/') = '\0'; // ==> '${pwd}/ASM'
		FILTERCF(strchr(absasmdir, '*'), verbose, LOG(WARN "try to remove director with wildcard\n"); break);
		FILTERCF(InjCallShellCmd(SHELL_RM, " -rf ", absasmdir, NULL, NULL, NULL, verbose) != RESCODE_SUCCESS, verbose, break);
		out->len = filesz;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(fp != NULL) fclose(fp);
		if(fd != -1) close(fd);
		if(out->addr){
			free(out->addr);
			out->addr = 0;
		}
		memset(out, 0, sizeof(*out));
	}
	return res;
}
API_PRIVATE ResCode InjGenAsmSftIntr(String *sftintrNew, AsmCmdType type, int verbose){
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	return InjGenAsmCom(sftintrNew, "int 3\n", "sftintr.s", " -g ASM/sftintr.s", "sftintr.o", type, verbose);
}
//generate jump asm code,
API_PRIVATE ResCode InjGenAsmJump(String *jmpNew, uintptr_t tgtaddr, AsmCmdType type, int verbose){
	char corecmd[MAX_ARGUMENTLEN] = { 0 };
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	FILTERC(sprintf(corecmd, "mov rax, %#lx\n", tgtaddr) <= 0, verbose, RESCODE_FAIL, return RESCODE_FAIL);
	FILTERC(strcat(corecmd, "jmp rax\n") <= 0, verbose, RESCODE_FAIL, return RESCODE_FAIL);
	return InjGenAsmCom(jmpNew, corecmd, "jmp.s", " -g ASM/jmp.s", "jmp.o", type, verbose);
}
//call shell command and output result to outfile,
///InjOpenFile
API_PRIVATE ResCode InjCallShellCmd(char *shellcmd, char *optargs, char *dir, char *outfile, int *fd, size_t *filesz, int verbose){
	ResCode res = RESCODE_FAIL;
	int tfd = -1;
	char cmdline[MAX_ARGUMENTLEN] = { 0 };
	if(shellcmd == NULL || dir == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, shellcmd, dir);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	errno = 0;
	do{
		struct stat statbuf;
		char *objpathname = NULL;
		char *cmdoptargs = NULL;
		if(outfile != NULL) FILTERC((objpathname = strcat(dir, outfile)) == NULL, verbose, RESCODE_FAIL, break);
		FILTERC((cmdoptargs = strcat(cmdline, shellcmd)) == NULL, verbose, RESCODE_FAIL, break);
		FILTERC((cmdoptargs = strcat(cmdline, optargs)) == NULL, verbose, RESCODE_FAIL, break);
		if(outfile == NULL) FILTERC((cmdoptargs = strcat(cmdline, dir)) == NULL, verbose, RESCODE_FAIL, break);
		if(outfile != NULL) FILTERC((cmdoptargs = strcat(cmdline, " -o ")) == NULL, verbose, RESCODE_FAIL, break);
		if(outfile != NULL) FILTERC((cmdoptargs = strcat(cmdline, objpathname)) == NULL, verbose, RESCODE_FAIL, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "cmdline: %s\n", cmdoptargs);
		system(cmdoptargs);
		if(fd != NULL && filesz != NULL){
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "checking file [%s]\n", objpathname);
			FILTERC(stat(objpathname, &statbuf) < 0, verbose, RESCODE_FAIL, LOG(ERROR "nasm expression syntax error\n"); break);
			FILTERCF(InjOpenFile(&tfd, objpathname, verbose) != RESCODE_SUCCESS, verbose, break);
			FILTERC(lseek(tfd, 0, SEEK_SET) < 0, verbose, RESCODE_FAIL_SEEK, break);
			*filesz = statbuf.st_size;
			*fd = tfd;
		}
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(tfd != -1) close(tfd);
	}
	return res;
}
//show asm code,
API_PRIVATE void InjShowAsmCmd(const AsmCmd *asmcmd){
	if(asmcmd == NULL) return;
	int num = asmcmd->num;
	const String *asms = &asmcmd->sftintr;
	LOG(DEBUG "%d asm code entries\n", num);
	if(num > 0) LOG(DEBUG "entries showed:\n");
	for(int i = 0; i < num; ++i){
		LOG(DEBUG "#%d: ", i+1);
		for(int j = 0; j < asms->len; ++j) LOG("%x ", asms->addr[j]);
		++asms;
		LOG("\n");
	}
}

//update libinfo for newly pushed library,
///InjOpenFile
///InjGetLinkMap
///InjLoadElfHdr
///InjLoadSecHdr
///InjLoadProHdr
API_PRIVATE ResCode InjUpdateLibs(Symbol **symtabNew, LibInfo *libinfo, ProgHdr *dynamic, SysFunc * sys, pid_t pid, int verbose){
	ResCode res = RESCODE_FAIL;
	int fd =-1;
	ElfInfo elf;
	LibNodes *node = NULL;
	if(symtabNew == NULL || libinfo == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, symtabNew, libinfo);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		errno = 0;
		memset(&elf, 0, sizeof(elf));
		FILTERCF(InjGetLinkMap(&libinfo->last, dynamic, pid, sys, verbose), verbose, break);
		FILTERCF(InjOpenFile(&fd, libinfo->last.l_name, verbose), verbose, break);
		FILTERCF(InjLoadElfHdr(&elf.elf, fd, verbose) != RESCODE_SUCCESS, verbose, break);
		FILTERCF(InjLoadSecHdr(&elf.sec, symtabNew, &elf, fd, verbose) != RESCODE_SUCCESS, verbose, break);
		SymNode *syms = (*symtabNew)->syms;
		struct link_map *lmap = &libinfo->last;
		for(int i = (*symtabNew)->num-1; i >= 0; --i) syms[i].addr += lmap->l_addr;
		FILTERC((node = malloc(sizeof(*node))) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		memset(node, 0, sizeof(*node));
		node->bgnaddr = lmap->l_addr;
		node->libname = strdup(lmap->l_name);
		FILTERC(node->libname == 0, verbose, RESCODE_FAIL, break);
		node->endaddr = syms[(*symtabNew)->num-1].addr + syms[(*symtabNew)->num-1].sz;
		node->type = MAPTYPE_SO;
		struct stat statbuf;
		memset(&statbuf, 0, sizeof(statbuf));
		FILTERC(stat(node->libname, &statbuf) < 0, verbose, RESCODE_FAIL, break);
		node->inode = statbuf.st_ino;
		FILTERCF(InjPushLibInfo(libinfo, node, verbose), verbose, break);
		free(elf.sec), elf.sec = NULL;
		close(fd), fd = -1;
		res = RESCODE_SUCCESS;
	}while(0);
	if(res != RESCODE_SUCCESS){
		if(node != NULL){
			if(node->libname) free(node->libname);
			free(node);
		}
		if(elf.sec) free(elf.sec);
		if(fd != -1) close(fd);
	}
	return res;
}
//get link_map of target process in running,
///InjLi*
API_PRIVATE ResCode InjGetLinkMap(struct link_map *linkmap, ProgHdr *dynamic, pid_t pid, SysFunc *sys, int verbose){
#define MAXSONAME sizeof(size_t)*8
	ResCode res = RESCODE_FAIL;
	char isattach = 0;
	char *libname = NULL;
	if(linkmap == NULL || dynamic == NULL || sys == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, linkmap, dynamic);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	do{
		Elf_Dyn dynbuf;
		uintptr_t dynentry = dynamic->vaddr;
		uintptr_t got = 0;
		errno = 0;
		memset(&dynbuf, 0, sizeof(dynbuf));
		FILTERCF(InjLiAttach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 1;
		FILTERCF(InjLiWait(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		//get linkmap from '_DYNAMIC'
		if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "searching PLTGOT in _DYNAMIC[%#lx]\n", dynentry);
		if(linkmap->l_prev == NULL){
			//find PLTGOT
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "get %d bytes from %#lx\n", (int)sizeof(dynbuf), dynentry);
			FILTERCF(InjLiReadDataOrText(pid, TRUE, dynentry, (uintptr_t)&dynbuf, sizeof(dynbuf), verbose)
					!= RESCODE_SUCCESS, verbose, break);
			while(dynbuf.d_tag != DT_PLTGOT && dynbuf.d_tag != DT_NULL){
				dynentry += sizeof(dynbuf);
				if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "get %d bytes from %#lx\n", (int)sizeof(dynbuf), dynentry);
				FILTERCF(InjLiReadDataOrText(pid, TRUE, dynentry, (uintptr_t)&dynbuf, sizeof(dynbuf), verbose)
						!= RESCODE_SUCCESS, verbose, goto out);
			}
			FILTERCF(dynbuf.d_tag == DT_NULL, verbose, LOG(ERROR "there is no PLTGOT in target process\n"); break;);
			got = dynbuf.d_un.d_ptr;
			if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "found PLTGOT at %#lx\n", got);

			//get linkmap in PLTGOT
			got += sizeof(uintptr_t);
			if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "get %d bytes from %#lx\n", (int)sizeof(dynbuf), got);
			FILTERCF(InjLiReadDataOrText(pid, TRUE, got, (uintptr_t)&got, sizeof(got), verbose) != RESCODE_SUCCESS, verbose, break);
			if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "found linkmap at %#lx\n", got);
			memset(linkmap, 0, sizeof(*linkmap));
			FILTERCF(InjLiReadDataOrText(pid, TRUE, got, (uintptr_t)linkmap, sizeof(*linkmap), verbose)
					!= RESCODE_SUCCESS, verbose, break);
		}
		else{//if we get linkmap before, use it to optimize
			FILTERCF(InjLiReadDataOrText(pid, TRUE, (uintptr_t)linkmap->l_prev, (uintptr_t)linkmap, sizeof(*linkmap), verbose)
					!= RESCODE_SUCCESS, verbose, break);
		}
		if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "searching the last linkmap\n");

		//find the last linkmap
		while(linkmap->l_next != NULL){
			if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "get %d bytes from %#lx\n", (int)sizeof(*linkmap), got);
			FILTERCF(InjLiReadDataOrText(pid, TRUE, (uintptr_t)linkmap->l_next, (uintptr_t)linkmap, sizeof(*linkmap), verbose)
					!= RESCODE_SUCCESS, verbose, goto out);
		}
		FILTERC((libname = malloc(MAXSONAME)) == NULL, verbose, RESCODE_FAIL_ALLOC, break);
		if(verbose >= LOGLEVEL_DEBUG) LOG(DEBUG "get %d bytes from %p\n", (int)MAXSONAME, linkmap->l_name);
		FILTERCF(InjLiReadDataOrText(pid, FALSE, (uintptr_t)linkmap->l_name, (uintptr_t)libname, MAXSONAME, verbose)
				!= RESCODE_SUCCESS, verbose, break);
		linkmap->l_name = libname;
		if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "last run-link library is [%s]\n", libname);

		FILTERCF(InjLiDetach(pid, verbose) != RESCODE_SUCCESS, verbose, break);
		isattach = 0;
		res = RESCODE_SUCCESS;
	}while(0);
out:
	if(res != RESCODE_SUCCESS){
		if(libname != NULL){ free(libname); linkmap->l_name = NULL; }
		if(linkmap->l_name){ free(linkmap->l_name); linkmap->l_name = 0; }
		if(isattach) InjLiDetach(pid, verbose);
	}
	return res;
}

//open file wrapper function,
API_PRIVATE ResCode InjOpenFile(int *fd, char *name, int verbose){
	int tfd = -1;
	if(verbose >= LOGLEVEL_TRACE) LOG(TRACE "Enter %s\n", __func__);
	if(fd == NULL || name == NULL){
		ELOG(RESCODE_FAIL_INVALID_ARGS, __LINE__, fd, name);
		return RESCODE_FAIL_INVALID_ARGS;
	}
	*fd = -1;
	tfd = open(name, O_RDONLY);
	if(tfd < 0) ELOG(RESCODE_FAIL_OPEN, __LINE__, name);
	else *fd = tfd;
	return RESCODE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
