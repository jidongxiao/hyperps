/*
 * This file includes the main function of the hyperps project.
 * Initial work by:
 *   (c) 2014 Jidong Xiao (jidong.xiao@gmail.com)
 *   (c) 2014 Lei Lu (lulei.wm@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include "hyperprobe/features.h"
//#include "hyperprobe/bugs.h"
//#include "hyperprobe/lib.h"
#include "hyperps/debug.h"

#ifndef DEBUG
#define DEBUG 0
#endif

unsigned long init_task=0xc16753a0;
void get_offsets(char *dumpfile);
void print_processes();

int main()
{
        DPRINTF("project kick-off!\n");
        get_offsets("dump.123");  // Get the offset of pid, process name, and next pointer
        print_processes(); // Print the process list of the monitoring Guest OS
	return 0;
}

//void get_offsets(char *dumpfile1, struct ps_info[])
void get_offsets(char *dumpfile1)
{
	FILE *ptr_dumpfile;
	unsigned char ptr[4096];
	unsigned long read_counter=0;
	unsigned long offset_of_name;
	void * ptr_name;
	char *name="swapper";
	ptr_dumpfile=fopen(dumpfile1,"rb");
	if (!ptr_dumpfile)
  	{
       		printf("Unable to open dump file!\n");
        	exit(1);
        }
	fseek(ptr_dumpfile,init_task,SEEK_SET);
	fread(ptr,4096,1,ptr_dumpfile);
//	strcpy(name,ps_info[0]->name);
	while( !feof(ptr_dumpfile) && (memmem(ptr,4096,name,sizeof(name))==NULL) )
	{
		fread(ptr,4096,1,ptr_dumpfile);
		read_counter++;
	}
	ptr_name=memmem(ptr,4096,name,sizeof(name));
	if(ptr_name==NULL)
	{
		printf("Couldn't find the process name!\n");
		fclose(ptr_dumpfile);
		exit(1);
	}
	offset_of_name=(void *)ptr_name-(void *)ptr+read_counter*4096;
	printf("Offset of process name is: %lx\n", offset_of_name);
	fclose(ptr_dumpfile);
//	while(*ptr!=ps_info[0]->pid)
//		fseek(ptr_dumpfile1,1,SEEK_CUR);
//	offset_of_pid=ftell(ptr_dumpfile1)-init_task;

//        memory[init_task+OFFSET_OF_PID]=ps_info[0]->pid;
//        memory[init_task+OFFSET_OF_NAME]=ps_info[0]->name;
//        memory[init_task+OFFSET_OF_NEXT+OFFSET_OF_PID]=ps_info[1]->init;
//        memory[init_task+OFFSET_OF_NEXT+OFFSET_OF_NAME]=ps_info[1]->name;
}

void print_processes()
{
}

