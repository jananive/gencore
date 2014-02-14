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

struct compat_elf_siginfo {
	int			si_signo;
	int			si_code;
	int			si_errno;
};

struct compat_timeval {
	int                             tv_sec;
	int                             tv_usec;
};

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

/* Power PC elf_gregset_t */
#define ELF_NGREG_PPC       48
typedef unsigned int elf_greg_t32_ppc;
typedef elf_greg_t32_ppc elf_gregset_t32_ppc[ELF_NGREG_PPC];
typedef elf_gregset_t32_ppc compat_elf_gregset_t_ppc;

/* x86 elf_gregset_t */
struct user_regs_struct32_x86 {
	unsigned int ebx, ecx, edx, esi, edi, ebp, eax;
	unsigned short ds, __ds, es, __es;
	unsigned short fs, __fs, gs, __gs;
	unsigned int orig_eax, eip;
	unsigned short cs, __cs;
	unsigned int eflags, esp;
	unsigned short ss, __ss;
};
typedef struct user_regs_struct32_x86 compat_elf_gregset_t_x86;

/* s390 elf_gregset_t */
#define NUM_GPRS        16
#define NUM_ACRS        16

typedef struct {
	unsigned int mask;
	unsigned int addr;
} __attribute__((aligned(8))) psw_compat_t;

typedef struct {
	psw_compat_t psw;
	unsigned int gprs[NUM_GPRS];
	unsigned int acrs[NUM_ACRS];
	unsigned int orig_gpr2;
} s390_compat_regs;

typedef s390_compat_regs compat_elf_gregset_t_s390;

#if defined(__PPC64__) || defined(__PPC__)
#define compat_elf_gregset_t compat_elf_gregset_t_ppc
#endif

#if defined(__s390x__) || defined(__s390__)
#define compat_elf_gregset_t compat_elf_gregset_t_s390
#endif

#if defined(__x86_64) || defined(__i386)
#define compat_elf_gregset_t compat_elf_gregset_t_x86
#endif

struct compat_elf_prstatus {
	struct compat_elf_siginfo	pr_info;
	short				pr_cursig;
	unsigned int			pr_sigpend;
	unsigned int			pr_sighold;
	int				pr_pid;
	int				pr_ppid;
	int				pr_pgrp;
	int				pr_sid;
	struct compat_timeval           pr_utime;
	struct compat_timeval           pr_stime;
	struct compat_timeval           pr_cutime;
	struct compat_timeval           pr_cstime;
	compat_elf_gregset_t		pr_reg;
	int				pr_fpvalid;
};
