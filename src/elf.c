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
#include <sys/uio.h>
#include <sys/procfs.h>
#include <linux/elf.h>
#include "elf-compat.h"
#include "coredump.h"

#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

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

int do_elf_coredump(int pid, struct core_proc *cp)
{
	int ret;

	/* Fill ELF Header */
	ret = fill_elf_header(pid, cp);
	if (ret)
		return -1;

	/* Get prps_info */
	ret = get_prpsinfo(pid, cp);
	if (ret)
		return -1;

	return 0;
}
