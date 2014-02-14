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
 */

/*
 * We include elf.c to add all the elf specific operations here.
 * In this file, we define all 32 bit specific data and hence
 * this file would contain all elf 32 bit specific functions
 * and operations once elf.c is included.
 */

#define do_elf_coredump do_elf32_coredump

#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Nhdr Elf32_Nhdr
#define Elf_prpsinfo compat_elf_prpsinfo
#define Elf_Long int

#include "elf.c"
