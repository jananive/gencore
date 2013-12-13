/*
 * ELF structures for gencore
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

#if defined(__PPC64__) || defined(__PPC__)
typedef unsigned int compat_id;
#endif

#if defined(__s390x__) || defined(__s390__)
typedef unsigned short compat_id;
#endif

#if defined(__x86_64) || defined(__i386)
typedef unsigned short compat_id;
#endif

/* Compat structure for PRPS_INFO */
struct compat_elf_prpsinfo {
	char				pr_state;
	char				pr_sname;
	char				pr_zomb;
	char				pr_nice;
	unsigned int			pr_flag;
	compat_id			pr_uid;
	compat_id			pr_gid;
	int				pr_pid, pr_ppid, pr_pgrp, pr_sid;
	char				pr_fname[16];
	char				pr_psargs[ELF_PRARGSZ];
};
