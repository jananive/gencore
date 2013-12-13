/*
 * ELF helper routines for gencore
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2013
 *
 * Authors:
 *      Janani Venkataraman <jananve@in.ibm.com>
 *      Suzuki K. Poulose <suzuki@in.ibm.com>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/procfs.h>
#include <sys/ptrace.h>
#include <linux/elf.h>
#include "elf-compat.h"
#include "coredump.h"

#define PAGESIZE getpagesize()

#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

#define ALIGN(addr, pagesize) (((addr) + (pagesize) - 1) & ~(pagesize - 1))

/* Default alignment for program headers */
#ifndef ELF_EXEC_PAGESIZE
#define ELF_EXEC_PAGESIZE PAGESIZE
#endif

/* Appending the note to the list */
static void append_note(struct mem_note *new_note, struct core_proc *cp)
{
	struct mem_note *tmp;

	if (cp->notes == NULL)
		cp->notes = new_note;
	else {
		tmp = cp->notes;
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = new_note;
	}
}

/* Adding a new note */
static int add_note(const char *name, int type, unsigned int data_sz, void *data,
						struct core_proc *cp)
{
	unsigned char *ptr, *notebuf;
	unsigned int namelen, size, data_offset;
	Elf_Nhdr *note;
	struct mem_note *tmp = malloc(sizeof(struct mem_note));
	if (!tmp) {
		status = errno;
		gencore_log("Failure in adding note.\n");
		return -1;
	}

	/* Calculate the size of the Notes */
	namelen = strlen(name) + 1;
	size = sizeof(Elf_Nhdr);
	size += namelen;

	/* Note down the offset where data is to be stored */
	data_offset = size = roundup(size, 4);
	size += data_sz;
	size = roundup(size, 4);

	/* Allocate the required size, initialized to 0 */
	notebuf = calloc(1, size);
	if (!notebuf) {
		status = errno;
		gencore_log("Could not allocate memory for Notes buffer.\n");
		return -1;
	}

	note = (Elf_Nhdr *)notebuf;

	/* Where name should be stored */
	ptr = (unsigned char *) (note + 1);

	note->n_type = type;
	note->n_namesz = strlen(name) + 1;
	note->n_descsz = data_sz;

	/* Store name */
	memcpy(ptr, name, namelen);

	/* Store data */
	memcpy(notebuf + data_offset, data, data_sz);

	tmp->notebuf = notebuf;
	tmp->size = size;
	tmp->next = NULL;

	append_note(tmp, cp);

	return 0;
}

/*
 * Reads first few bytes of the address specified and checks if it is
 * an ELF by checking the magic number.
 */
static int get_elf_hdr_vaddr(int pid, Elf_Ehdr *elf, Elf_Addr addr)
{
	int ret;
	struct iovec local, remote;

	local.iov_base = elf;
	local.iov_len = sizeof(Elf_Ehdr);
	remote.iov_base = (void *)addr;
	remote.iov_len = sizeof(Elf_Ehdr);
	ret = process_vm_readv(pid, &local, 1, &remote, 1, 0);
	if (ret == -1)
		return -1;

	return check_elf_hdr(elf->e_ident);
}

/* Fetchs ELF header of the executable */
static int get_elf_hdr_exe_file(int pid, Elf_Ehdr *elf)
{
	char filename[40];
	int ret;
	FILE *fin;

	snprintf(filename, 40, "/proc/%d/exe", pid);
	fin = fopen(filename, "r");
	if (fin == NULL) {
		status = errno;
		gencore_log("Failed to open %s for checking the ELF header.",
								filename);
		return -1;
	}

	ret = fread(elf, sizeof(*elf), 1, fin);
	if (ret != 1) {
		status = errno;
		gencore_log("Failure while fetching the ELF header of the executable from %s.\n", filename);
		fclose(fin);
		return -1;
	}

	fclose(fin);

	return 0;
}

/* Fills the ELF HEADER */
static int fill_elf_header(int pid, struct core_proc *cp)
{
	Elf_Ehdr elf, *cp_elf;
	int ret;

	cp->elf_hdr = malloc(sizeof(Elf_Ehdr));
	if (!cp->elf_hdr) {
		status = errno;
		gencore_log("Failure in allocating memory for ELF header.\n");
		return -1;
	}

	cp_elf = (Elf_Ehdr *)cp->elf_hdr;

	memset(cp_elf, 0, EI_NIDENT);

	ret = get_elf_hdr_exe_file(pid, &elf);
	if (ret == -1)
		return -1;

	/* Magic Number */
	memcpy(cp_elf->e_ident, ELFMAG, SELFMAG);

	cp_elf->e_ident[EI_CLASS] = elf.e_ident[EI_CLASS];
	cp_elf->e_ident[EI_DATA] = elf.e_ident[EI_DATA];
	cp_elf->e_ident[EI_VERSION] = EV_CURRENT;
	cp_elf->e_ident[EI_OSABI] = EI_OSABI;

	/* Rest of the fields */
	cp_elf->e_entry = 0;
	cp_elf->e_type = ET_CORE;
	cp_elf->e_machine = elf.e_machine;
	cp_elf->e_version = EV_CURRENT;
	cp_elf->e_phoff = sizeof(Elf_Ehdr);
	cp_elf->e_shoff = 0;
	cp_elf->e_flags = 0;
	cp_elf->e_ehsize =  sizeof(Elf_Ehdr);
	cp_elf->e_phentsize = sizeof(Elf_Phdr);

	if (cp->phdrs_count > PN_XNUM) {
		cp_elf->e_phnum = PN_XNUM;
		cp_elf->e_shentsize = sizeof(Elf_Shdr);
		cp_elf->e_shnum = 1;
	} else {
		cp_elf->e_phnum = cp->phdrs_count;
		cp_elf->e_shentsize = 0;
		cp_elf->e_shnum = 0;
	}

	cp_elf->e_shstrndx = SHN_UNDEF;

	return 0;
}

/* Populates PRPS_INFO */
static int get_prpsinfo(int pid, struct core_proc *cp)
{
	char filename[40];
	int ret;
	FILE *fin;
	struct Elf_prpsinfo prps;
	struct pid_stat p;

	ret = get_pid_stat(pid, &p);
	if (ret)
		return -1;

	prps.pr_pid = p.ps_pid;
	strcpy(prps.pr_fname, p.ps_comm);
	prps.pr_state = p.ps_state;
	prps.pr_ppid = p.__ps_ppid;
	prps.pr_pgrp = p.__ps_pgrp;
	prps.pr_sid = p.__ps_sid;
	prps.pr_flag = p.__ps_flag;
	prps.pr_nice = p.__ps_nice;

	prps.pr_sname = prps.pr_state;
	if (prps.pr_sname == 'z')
		prps.pr_zomb = 1;
	else
		prps.pr_zomb = 0;

	snprintf(filename, 40, "/proc/%d/cmdline", pid);
	fin = fopen(filename, "r");
	if (fin == NULL) {
		status = errno;
		gencore_log("Failure while fetching command line arguments from %s.\n", filename);
		return -1;
	}

	/* Getting CMDLINE arguments */
	ret = fread(prps.pr_psargs, ELF_PRARGSZ, 1, fin);
	if (ret == -1) {
		status = errno;
		gencore_log("Failure while fetching command line arguments from %s.\n", filename);
		fclose(fin);
		return -1;
	}

	fclose(fin);

	/* Adding PRPSINFO */
	return add_note("CORE", NT_PRPSINFO, sizeof(prps), &prps, cp);
}

/* Populate auxillary vector */
static int get_auxv(int pid, struct core_proc *cp)
{
	unsigned char buff[PAGESIZE];
	char filename[40];
	int ret, fd, pages;
	unsigned char *ptr, *auxv;
	unsigned int auxv_size;

	snprintf(filename, 40, "/proc/%d/auxv", pid);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		status = errno;
		gencore_log("Failure while fetching auxv data from %s.\n",
								filename);
		return -1;
	}

	auxv = malloc(PAGESIZE);
	if (!auxv) {
		status = errno;
		gencore_log("Could not allocate memory for the auxv_buffer.\n");
		close(fd);
		return -1;
	}
	/* Position to copy the auxv data */
	ptr = auxv;
	pages = 1;
	/*
	 * We read the auxv data page by page and also we don't not
	 * know the size of auxv, hence we read till ret becomes
	 * lesser than PAGESIZE.
	 */
	while ((ret = read(fd, buff, PAGESIZE)) > 0) {
		memcpy(ptr, buff, ret);
		if (ret < PAGESIZE)   /* Finished reading */
			break;
		else {
			/* We have more data to read */
			pages++;
			auxv = realloc(auxv, pages * PAGESIZE);
			ptr = auxv + ((pages - 1) * PAGESIZE);
		}
	}
	if (ret >= 0)
		auxv_size = ((pages - 1) * PAGESIZE) + ret;
	else {
		status = errno;
		gencore_log("Failure while fetching auxv data from %s.\n", filename);
		close(fd);
		free(auxv);
		return -1;
	}

	/* Adding AUXV */
	ret = add_note("CORE", NT_AUXV, auxv_size, auxv, cp);

	close(fd);
	free(auxv);

	return ret;
}

/*
 * Get File Maps in the following format:
 * long count     -- how many files are mapped
 * long page_size -- units for file_ofs
 * array of [COUNT] elements of
 * long start
 * long end
 * long file_ofs
 * followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
 */
static int get_file_maps(struct core_proc *cp)
{
	Elf_Long count = 0;
	Elf_Long fmap_size = 0, namesz = 0;
	Elf_Long *fmap;
	Elf_Long *data_pos;
	unsigned char *name_pos;
	int ret;
	struct maps *map = cp->vmas;

	/*
	 * Finding the actual size of the file map for which we need
	 * to know number of VMAS(non zero inode) plus the file name size
	 * for each of the VMAS(non zero inode.
	 */
	while (map) {
		if (map->inode) {
			count++;
			namesz += strlen(map->fname) + 1;
		}
		map = map->next;
	}

	/*
	 * We add 2 for the count and page_size, 3 * (number of vmas)
	 * for the start, end and file_ofs and finally the entire size
	 * of the filenames of all the VMAS.
	 */
	fmap_size = ((2 + (3 * count)) * sizeof(Elf_Long))
				+ (namesz * sizeof(unsigned char));

	fmap = calloc(fmap_size, 1);
	if (!fmap) {
		status = errno;
		gencore_log("Could not allocate memory for file map data\n");
		return -1;
	}

	data_pos = fmap + 2;
	name_pos = (unsigned char *)(fmap + 2 + (count * 3));

	map = cp->vmas;
	while (map) {
		if (map->inode) {
			*data_pos++ = map->src;
			*data_pos++ = map->dst;
			*data_pos++ = map->offset;

			strcpy(name_pos, map->fname);
			name_pos += strlen(map->fname) + 1;
		}
		map = map->next;
	}

	fmap[0] = count;
	fmap[1] = 1;

	ret = add_note("CORE", NT_FILE, fmap_size, fmap, cp);
	free(fmap);

	return ret;
}

/* Getting Registers */
static int get_regset(int tid, int regset, struct iovec *iov)
{
	return ptrace(PTRACE_GETREGSET, tid, regset, iov);
}

/* Fetching Note */
static int fetch_note(int regset, const char *name, struct core_proc *cp, int tid)
{
	int ret = 0;
	int size = PAGESIZE;
	struct iovec iov;
	void *data;
	data = malloc(PAGESIZE);
	if (!data)
		return -1;

	/*
	 * The size of regset being fetched may be greater than size,
	 * which is initially PAGESIZE. The iov_len gets reset to the
	 * amount of data read by PTRACE_GETREGSET. If the iov_len is
	 * equal to size, in that case, there is more data to read and
	 * hence we increase the size and try reading again. The moment
	 * iov.len is lesser than size, we break out of the loop as all
	 * the data is read
	 */
	while (1) {
		iov.iov_base = data;
		iov.iov_len = size;
		ret = get_regset(cp->t_id[tid], (unsigned int) regset,
							&iov);
		if (ret)
			break;
		if (iov.iov_len < size)
			break;
		size += PAGESIZE;
		data = realloc(data, size);
		if (!data)
			return -1;
	}

	/* Adding Note */
	if (ret == 0)
		ret = add_note(name, regset, iov.iov_len, data, cp);

	free(data);

	return ret;
}

/* Populates PRSTATUS for the threads */
static int fill_core_notes(int tid, struct core_proc *cp)
{
	/* PRSTATUS */
	struct iovec iov;
	int ret;
	struct Elf_prstatus prstat;
	struct pid_stat p;
	char state;

	ret = get_pid_stat(cp->t_id[tid], &p);
	if (ret)
		return -1;

	prstat.pr_pid = p.ps_pid;
	prstat.pr_ppid = p.__ps_ppid;
	prstat.pr_pgrp = p.__ps_pgrp;
	prstat.pr_sid = p.__ps_sid;
	prstat.pr_utime.tv_sec = p.__ps_utime;
	prstat.pr_stime.tv_sec = p.__ps_stime;
	prstat.pr_cutime.tv_sec = p.__ps_cutime;
	prstat.pr_cstime.tv_sec = p.__ps_cstime;
	prstat.pr_sigpend = p.__ps_sigpend;
	prstat.pr_sighold = p.__ps_sighold;

	/* General Purpose registers */
	iov.iov_base = &prstat.pr_reg;
	iov.iov_len =  sizeof(prstat.pr_reg);
	ret = get_regset(cp->t_id[tid], NT_PRSTATUS, &iov);
	if (ret == -1) {
		state = get_thread_status(cp->t_id[tid]);
		if (state != 'Z') {
			status = errno;
			gencore_log("Failure in fetching General Purpose registers for Thread:%d.\n", tid);
			return -1;
		}
	}

	prstat.pr_info.si_signo = 0;

	/* FP_REGSET */
	ret = fetch_note(NT_PRFPREG, "CORE", cp, tid);
	if ( ret == 0)
		prstat.pr_fpvalid = 1;
	else
		prstat.pr_fpvalid = 0;
		
	/* Adding PRSTATUS */
	return add_note("CORE", NT_PRSTATUS, sizeof(prstat),
						&prstat, cp);
}

/* X86 Specific Notes */
static void fetch_x86_notes(struct core_proc *cp, int tid)
{
	int notes[] = {
			NT_X86_XSTATE,
			NT_386_TLS,
			0};
	int i;

	for (i = 0; notes[i]; i++)
		(void)fetch_note(notes[i], "LINUX", cp, tid);
}

/* PPC Specific Notes */
static void fetch_ppc_notes(struct core_proc *cp, int tid)
{
	int notes[] = {
			NT_PPC_VMX,
			NT_PPC_SPE,
			NT_PPC_VSX,
			0};
	int i;

	for (i = 0; notes[i]; i++)
		(void)fetch_note(notes[i], "LINUX", cp, tid);
}

/* S390 Specific Notes */
static void fetch_s390_notes(struct core_proc *cp, int tid)
{
	int notes[] = {
			NT_S390_HIGH_GPRS,
			NT_S390_TIMER,
			NT_S390_LAST_BREAK,
			NT_S390_SYSTEM_CALL,
			NT_S390_TODCMP,
			NT_S390_TODPREG,
			NT_S390_CTRS,
			NT_S390_PREFIX,
			0};
	int i;

	for (i = 0; notes[i]; i++)
		(void)fetch_note(notes[i], "LINUX", cp, tid);
}

/* Fetching thread specific notes */
static int fetch_thread_notes(struct core_proc *cp)
{
	int tid, ret;

	Elf_Ehdr *cp_elf;
	cp_elf = (Elf_Ehdr *)cp->elf_hdr;

	/*
	 * The architecture specific notes are optional and they may or may not
	 * be present. Hence we do not check if we were successful in fetching
	 * them or not.
	 */

	for (tid = 0; tid < cp->thread_count; tid++) {
		ret = fill_core_notes(tid, cp);
		if (ret)
			return -1;

		switch (cp_elf->e_machine) {
		case EM_X86_64:
		case EM_386:
			fetch_x86_notes(cp, tid);
			break;
		case EM_PPC:
		case EM_PPC64:
			fetch_ppc_notes(cp, tid);
			break;
		case EM_S390:
			fetch_s390_notes(cp, tid);
			break;
		}

	}

	return 0;
}

/* Populate Program headers */
static int get_phdrs(int pid, struct core_proc *cp)
{
	int n;
	struct maps *map = cp->vmas;
	Elf_Ehdr elf;
	Elf_Phdr *cp_phdrs;
	Elf_Shdr *cp_shdrs;
	Elf_Ehdr *cp_elf;
	cp_elf = (Elf_Ehdr *)cp->elf_hdr;

	cp->phdrs = calloc(cp->phdrs_count, sizeof(Elf_Phdr));
	if (!cp->phdrs) {
		status = errno;
		gencore_log("Could not allocate memory for Program headers.\n");
		return -1;
	}

	cp_phdrs = (Elf_Phdr *)cp->phdrs;

	cp_phdrs[0].p_type = PT_NOTE;
	cp_phdrs[0].p_offset = 0;
	cp_phdrs[0].p_vaddr = 0;
	cp_phdrs[0].p_paddr = 0;
	cp_phdrs[0].p_filesz = 0;
	cp_phdrs[0].p_memsz = 0;

	n = 1;

	while (map) {

		/* Filling the Program Header Values */
		cp_phdrs[n].p_type = PT_LOAD;
		cp_phdrs[n].p_offset = 0;
		cp_phdrs[n].p_vaddr = map->src;
		cp_phdrs[n].p_paddr = 0;
		cp_phdrs[n].p_flags = 0;
		if (map->r == 'r')
			cp_phdrs[n].p_flags |= PF_R;
		if (map->w == 'w')
			cp_phdrs[n].p_flags |= PF_W;
		if (map->x == 'x')
			cp_phdrs[n].p_flags |= PF_X;

		cp_phdrs[n].p_memsz = map->dst - map->src;

		if (!(cp_phdrs[n].p_flags & PF_R))
			cp_phdrs[n].p_filesz = 0;
		else if (map->inode &&
			get_elf_hdr_vaddr(pid, &elf, cp_phdrs[n].p_vaddr) == 0)
			cp_phdrs[n].p_filesz = ELF_EXEC_PAGESIZE;
		else
			cp_phdrs[n].p_filesz = cp_phdrs[n].p_memsz;
		
		cp_phdrs[n].p_align = ELF_EXEC_PAGESIZE;

		n++;
		map = map->next;
	}

	if (cp->phdrs_count > PN_XNUM) {
		cp->shdrs = malloc(sizeof(Elf_Shdr));
		if (!cp->shdrs) {
			status = errno;
			gencore_log("Could not allocate memory for Extra Program headers.\n");
			return -1;
		}
		cp_shdrs = (Elf_Shdr *)cp->shdrs;
		cp_shdrs->sh_type = SHT_NULL;
		cp_shdrs->sh_size = cp_elf->e_shnum;
		cp_shdrs->sh_link = cp_elf->e_shstrndx;
		cp_shdrs->sh_info = cp->phdrs_count;
	}

	return 0;
}

/* Updating the Offset */
static void update_offset(struct core_proc *cp)
{
	Elf_Long data_offset = 0;
	struct mem_note *note = cp->notes;
	int i;
	Elf_Phdr *cp_phdrs;
	Elf_Ehdr *cp_elf;

	cp_elf = (Elf_Ehdr *)cp->elf_hdr;
	cp_phdrs = (Elf_Phdr *)cp->phdrs;

	/* ELF HEADER */
	data_offset += sizeof(Elf_Ehdr);

	/* Program Headers */
	data_offset += cp->phdrs_count * sizeof(Elf_Phdr);

	/* Notes */
	cp_phdrs[0].p_offset = data_offset;

	/* Calucalating entire NOTES size */
	while (note) {
		data_offset += note->size;
		note = note->next;
	}

	/* Filling PT_NOTE size */
	cp_phdrs[0].p_filesz = data_offset - cp_phdrs[0].p_offset;

	data_offset = ALIGN(data_offset, ELF_EXEC_PAGESIZE);

	/* Populating offsets of Program Headers */
	for (i = 1; i < cp->phdrs_count; i++) {
		cp_phdrs[i].p_offset = data_offset;
		data_offset += cp_phdrs[i].p_filesz;
		data_offset = ALIGN(data_offset, ELF_EXEC_PAGESIZE);
	}

	/* Filling extra program header offset if phnum > PN_XNUM */
	if (cp->phdrs_count > PN_XNUM)
		cp_elf->e_shoff = data_offset;
}

int do_elf_coredump(int pid, struct core_proc *cp)
{
	int ret, i;

	/* Fill ELF Header */
	ret = fill_elf_header(pid, cp);
	if (ret)
		return -1;

	/* Get prps_info */
	ret = get_prpsinfo(pid, cp);
	if (ret)
		return -1;

	/* Get Auxillary Vector */
	ret = get_auxv(pid, cp);
	if (ret)
		return -1;

	/* Get File maps */
	ret = get_file_maps(cp);
	if (ret)
		return -1;

	/* Get the thread specific notes */
	ret = fetch_thread_notes(cp);
	if (ret)
		return -1;

	/* Get Program headers */
	ret = get_phdrs(pid, cp);
	if (ret)
		return -1;

	/* Updating offset */
	update_offset(cp);

	return 0;
}
