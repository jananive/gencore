/*
 * /proc/ helper routines for gencore
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <coredump.h>

/* Get Process Stats */
int get_pid_stat(int pid, struct pid_stat *ps)
{
	int ret = -1, i;
	char junk;
	char filename[40];
	FILE *fin;

	snprintf(filename, 40, "/proc/%d/stat", pid);
	fin = fopen(filename, "r");
	if (fin == NULL) {
		status = errno;
		gencore_log("Failure while fetching thread status from %s.\n",
								filename);
		return -1;
	}

	/* Read pid */
	fscanf(fin, "%d", &ps->ps_pid);

	/* Skip till '(' */
	while (fscanf(fin, "%c", &junk) != EOF && junk != '(');
	if (junk != '(')  {
		status = errno;
		gencore_log("Failure while fetching thread status from %s.\n",
								filename);
		goto err;
	}

	/* Read Command Line */
	fscanf(fin, "%[^)]", ps->ps_comm);

	/* Skip the ')' */
	while (fscanf(fin, "%c", &junk) != EOF && junk != ')');
	if (junk != ')')  {
		status = errno;
		gencore_log("Failure while fetching thread status from %s.\n",
								filename);
		goto err;
	}

	/* Reading the space */
	fscanf(fin, "%c", &junk);

	/* State */
	fscanf(fin, "%c", &ps->ps_state);

	/* Read the rest of the fields */
	for (i = 0; i < NUM_STAT_FEILDS &&
			(fscanf(fin, "%lld", &ps->ps_num[i]) != EOF); i++);

	if (i == NUM_STAT_FEILDS)
		ret = 0;

err:
	fclose(fin);
	return ret;
}

/* Counts the number of threads in the process */
int get_thread_count(int pid)
{
	struct pid_stat p;
	int ret;

	ret = get_pid_stat(pid, &p);
	if (ret)
		return -1;

	return p.__ps_thread_count;
}

/* Fetched thread status */
char get_thread_status(int tid)
{
	int ret;
	char filename[40], buff[40];
	FILE *fin;
	char *pos;

	snprintf(filename, 40, "/proc/%d/stat", tid);
	fin = fopen(filename, "r");
	if (fin == NULL) {
		status = errno;
		gencore_log("Failure while fetching thread state from %s.\n",
								filename);
		return -1;
	}

	ret = fread(buff, 40, 1, fin);
	if (ret == 0) {
		status = errno;
		gencore_log("Failure while fetching thread state from %s.\n",
								filename);
		return -1;
	}

	pos = strrchr(buff, ')');
	if (pos == NULL) {
		status = errno;
		gencore_log("Failure while fetching thread state from %s.\n",
								filename);
		return -1;
	}

	fclose(fin);

	return buff[pos - buff + 2];
}

/* Free Maps */
void free_maps(struct maps *head)
{
	struct maps *tmp;

	while (head) {
		tmp = head->next;
		free(head);
		head = tmp;
	}
}

/* Append a new VMA */
void append_maps(struct maps *new_map, struct core_proc *cp)
{
	struct maps *tmp;

	if (cp->vmas == NULL)
		cp->vmas = new_map;
	else {
		tmp = cp->vmas;
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = new_map;
	}
}

/* Collects virtual memory areas */
int get_vmas(int pid, struct core_proc *cp)
{
	char filename[40];
	char buff[4096];
	char src[128];
	char dst[128];
	char fname[4096];
	char page_offset[128];
	char inode[128];
	char r, w, x;
	char junk[30];
	FILE *fin;
	struct maps *tmp;
	long tmp_inode;

	snprintf(filename, 40, "/proc/%d/maps", pid);
	fin = fopen(filename, "r");
	if (fin == NULL) {
		status = errno;
		gencore_log("Failure in fetching Memory Mappings %s.\n",
								filename);
		return -1;
	}

	while (fgets(buff, 4096, fin)) {

		sscanf(buff, "%[^-]%c%s %c%c%c%c %s %s %s %s", src, &junk[0],
					dst, &r, &w, &x, &junk[0],
					page_offset, junk, inode, fname);

		tmp_inode = strtol(inode, NULL, 16);

		if (tmp_inode)
			tmp = malloc(sizeof(struct maps) + strlen(fname) + 1);
		else
			tmp = malloc(sizeof(struct maps));
		if (!tmp) {
			status = errno;
			gencore_log("Failure in allocating memory for memory maps.\n");
			fclose(fin);
			return -1;
		}

		tmp->src = strtoull(src, NULL, 16);
		tmp->dst = strtoull(dst, NULL, 16);
		tmp->offset = strtoull(page_offset, NULL, 16);
		tmp->r = r;
		tmp->w = w;
		tmp->x = x;
		tmp->inode = tmp_inode;

		if (tmp->inode != 0)
			strcpy(tmp->fname, fname);

		tmp->next = NULL;
		append_maps(tmp, cp);
		cp->phdrs_count++;
	}

	/* One extra for the PT_NOTE */
	cp->phdrs_count++;

	fclose(fin);
	return 0;
}
