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
#include "hyperps/debug.h"

#ifndef DEBUG
#define DEBUG 0
#endif

unsigned long init_task=0x16753a0;
unsigned long offset_of_name;
unsigned long offset_of_next;
unsigned long offset_of_pid;
void get_offsets(char *dumpfile);
void print_processes(char *dumpfile);

int main()
{
        DPRINTF("project kick-off!\n");
        get_offsets("dump.123");  // Get the offset of pid, process name, and next pointer
        print_processes("dump.123"); // Print the process list of the monitoring Guest OS
	return 0;
}

//void get_offsets(char *dumpfile1, struct ps_info[])
void get_offsets(char *dumpfile1)
{
	FILE *ptr_dumpfile;
	unsigned char ptr[4096];	// When we calculate the offset of process name, we call fread and store the output in ptr[]
	unsigned long ptr_next[1];	// When we calculate the offset of next pointer, we call fread and store the output in ptr_next[]
	unsigned long ptr_pid[1];	// When we calculate the offset of pid, we call fread and store the output in ptr_pid[]
	unsigned long ptr_next_next[1];	// When we calculate the offset of pid, we need to compare one more time, since the first pid is 0, 
					// the second pid is 1, they appears in the memory too often, therefore we go one more step and verify the next pid is 2.
	unsigned long ptr_pid_next[1];
	unsigned long read_counter=0;
	void * ptr_name;
	char *name="swapper";		// This is pid=0 process, in Linux.
	char *name1="init";		// This is the pid=1 process, in Linux.
	ptr_dumpfile=fopen(dumpfile1,"rb");
	if (!ptr_dumpfile)
  	{
       		printf("Unable to open dump file!\n");
        	exit(1);
        }

	/* Compute the offset of the process name */
	fseek(ptr_dumpfile,init_task,SEEK_SET);
	while( !feof(ptr_dumpfile) )
	{
		fread(ptr,4096,1,ptr_dumpfile);
		if( (memmem(ptr,4096,name,strlen(name)) != NULL) ) 
			break;
		read_counter++;
	}
	ptr_name=memmem(ptr,4096,name,strlen(name));
	if(ptr_name==NULL)
	{
		printf("Couldn't find the process name!\n");
		fclose(ptr_dumpfile);
		exit(1);
	}
	offset_of_name=(void *)ptr_name-(void *)ptr+read_counter*4096;
	printf("Offset of process name is: 0x%lx\n", offset_of_name);

	/* Compute the offset of the next pointer */
	read_counter=0;
	fseek(ptr_dumpfile,init_task,SEEK_SET);
        while( !feof(ptr_dumpfile) )
        {
                fread(ptr_next,4,1,ptr_dumpfile);
		unsigned long ptr_mark=ftell(ptr_dumpfile);
		if(*ptr_next>0xc0000000)
		{
//			printf("Value of next pointer is: 0x%lx\n", *ptr_next);
			offset_of_next=read_counter*4;
			fseek(ptr_dumpfile,*ptr_next-0xc0000000-offset_of_next,SEEK_SET);
			fread(ptr,4096,1,ptr_dumpfile);
			if( (void *)memmem(ptr,4096,name1,strlen(name1)) - (void *)ptr == offset_of_name )
			{
				printf("Yes we found the next process name\n");
				printf("Therefore, we assert that the offset of the next pointer is: 0x%lx\n", offset_of_next);
				break;
			}
		}
                read_counter++;
		fseek(ptr_dumpfile,ptr_mark,SEEK_SET);	// We need to go back to the original location and continue our fread.
//	if(read_counter>120)
//	break;
        }

	/* Compute the offset of the pid */
	read_counter=0;
	fseek(ptr_dumpfile,init_task,SEEK_SET);
        while( !feof(ptr_dumpfile) )
        {
                fread(ptr_pid,4,1,ptr_dumpfile);
		unsigned long ptr_mark=ftell(ptr_dumpfile);
		if(*ptr_pid==0)
		{
			offset_of_pid=read_counter*4;
			fseek(ptr_dumpfile,*ptr_next-0xc0000000-offset_of_next+offset_of_pid,SEEK_SET);
                	fread(ptr_pid,4,1,ptr_dumpfile);
			if(*ptr_pid==1)
			{
				fseek(ptr_dumpfile,*ptr_next-0xc0000000,SEEK_SET);
				fread(ptr_next_next,4,1,ptr_dumpfile);
				fseek(ptr_dumpfile,*ptr_next_next-0xc0000000-offset_of_next+offset_of_pid,SEEK_SET);
                		fread(ptr_pid_next,4,1,ptr_dumpfile);
				if(*ptr_pid_next==2)
				{
					printf("Yes we found the next pid.\n");
					printf("Therefore, we assert that the offset of the pid is: 0x%lx\n", offset_of_pid);
					break;
				}
			}
		}
		read_counter++;	
		fseek(ptr_dumpfile,ptr_mark,SEEK_SET);	// We need to go back to the original location and continue our fread.
//	if(read_counter>120)
//	break;
	}

	fclose(ptr_dumpfile);

}

void print_processes(char *dumpfile2)
{
	FILE *ptr_dumpfile;
	unsigned char ptr[4096];
	unsigned long ptr_next[1];
	unsigned long ptr_pid[1];
	unsigned long print_counter=0;
	ptr_dumpfile=fopen(dumpfile2,"rb");
        if (!ptr_dumpfile)
        {
                printf("Unable to open dump file!\n");
                exit(1);
        }

	printf("PID PROCESS_NAME\n");
	fseek(ptr_dumpfile,init_task,SEEK_SET);
	while(1)
	{
		unsigned long ptr_mark=ftell(ptr_dumpfile);
		fseek(ptr_dumpfile,ptr_mark+offset_of_pid,SEEK_SET);
               	fread(ptr_pid,4,1,ptr_dumpfile);
		printf("%ld ",*ptr_pid);
		fseek(ptr_dumpfile,ptr_mark+offset_of_name,SEEK_SET);
		fread(ptr,4096,1,ptr_dumpfile);
		printf("%s\n",ptr);
		fseek(ptr_dumpfile,ptr_mark+offset_of_next,SEEK_SET);
                fread(ptr_next,4,1,ptr_dumpfile);
		fseek(ptr_dumpfile,*ptr_next-0xc0000000-offset_of_next,SEEK_SET);
		print_counter++;
		if(print_counter>20)
			break;
	}
	fclose(ptr_dumpfile);
}

