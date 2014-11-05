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

#define BUFFER_SIZE 4096
#define KERNEL_BASE 0xC0000000

#ifndef DEBUG
#define DEBUG 0
#endif

unsigned long init_task=0x16753a0;
long offset_of_name;
long offset_of_next;
unsigned long offset_of_pid;
void get_offsets(FILE *dumpfile);
void print_processes(char *dumpfile);

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: %s image_path\n", argv[0]);
	} else {
		DPRINTF("project kick-off!\n");
		
		FILE* dumpfile = fopen(argv[1], "rb");
		if (!dumpfile) {
       		printf("Unable to open dump file: %s\n", argv[1]);
        	return -1;
		}

		printf("==================Get Process Offset from the Trusted OS=======================\n");	

		get_offsets(dumpfile);  // Get the offset of pid, process name, and next pointer
		fclose(dumpfile);

		printf("===============================================================================\n");
		printf("                                                                               \n");
		printf("===============================================================================\n");
		printf("==================Print Processes of the Monitoring OS=========================\n");
		print_processes(argv[1]); // Print the process list of the monitoring Guest OS
	}	
	return 0;
}

long get_offset_of_name(FILE * fd, char* buffer, char* target_name) 
{
	long read_counter = 0;
	long offset = -1;
	char* name_pos = NULL;

	fseek(fd, init_task, SEEK_SET);
	
	while (!feof(fd)) {
		fread(buffer, BUFFER_SIZE, 1, fd);
		name_pos = (char*) memmem(buffer, BUFFER_SIZE, target_name, strlen(target_name));
		if (name_pos != NULL)
			break;
		read_counter++;
	}

	if (name_pos == NULL) {
		printf("Couldn't find the process name!\n");
		fclose(fd);
		return -1;
	}

	offset = name_pos - buffer + read_counter * BUFFER_SIZE;
	return offset;
}

long get_offset_of_next(FILE* fd, char* ptr_next, char* buffer, char* process_1) {
	long read_counter = 0;
	unsigned long ptr_mark = 0;
	long offset = -1;

	fseek(fd, init_task, SEEK_SET);

	while (!feof(fd)) {
		// read another 4 bytes and assume it is a pointer
		fread(ptr_next, 4, 1, fd);
		ptr_mark = ftell(fd);

		//if the pointer points to the kernel space
		if (*((unsigned long*) ptr_next) > KERNEL_BASE) {
			offset = read_counter * 4;
			fseek(fd, *((unsigned long*)ptr_next) - KERNEL_BASE - offset, SEEK_SET);
			fread(buffer, BUFFER_SIZE, 1, fd);
			if ((void *)memmem(buffer, BUFFER_SIZE, process_1, strlen(process_1)) - (void *)buffer == offset_of_name) {
				printf("Yes we found the next process name\n");
				printf("Therefore, we assert that the offset of the next pointer is: 0x%lx\n", offset);
				break;
			}
		}

        read_counter++;
		fseek(fd, ptr_mark, SEEK_SET);	// We need to go back to the original location and continue our fread.
    }
	return offset;
}

long get_offset_of_pid (FILE *fd, char* ptr_next, char *ptr_pid, char *ptr_next_next, char *ptr_pid_next) {
	long read_counter = 0;
	long offset = -1;

	fseek(fd, init_task, SEEK_SET);

    while (!feof(fd)) {
		fread(ptr_pid, 4, 1, fd);
		unsigned long ptr_mark = ftell(fd);
		if (*((unsigned long*)ptr_pid) == 0) {
			offset = read_counter * 4;
			fseek(fd, *((unsigned long*)ptr_next) - KERNEL_BASE - offset_of_next + offset, SEEK_SET);
            fread(ptr_pid, 4, 1, fd);
		
			if (*((unsigned long*)ptr_pid) == 1) {
				fseek(fd, *((unsigned long*)ptr_next) - KERNEL_BASE, SEEK_SET);
				fread(ptr_next_next, 4, 1, fd);
				fseek(fd, *((unsigned long*)ptr_next_next) - KERNEL_BASE - offset_of_next + offset, SEEK_SET);
                fread(ptr_pid_next, 4, 1, fd);

				if (*((unsigned long*)ptr_pid_next) == 2) {
					printf("Yes we found the next pid.\n");
					printf("Therefore, we assert that the offset of the pid is: 0x%lx\n", offset);
					break;
				}
			}
		}
		read_counter++;	
		fseek(fd, ptr_mark, SEEK_SET);	// We need to go back to the original location and continue our fread.
	}
	return offset;
}

void get_offsets(FILE *dumpfile)
{
	char ptr[BUFFER_SIZE];	// When we calculate the offset of process name, we call fread and store the output in ptr[]
	char ptr_next[4];	// When we calculate the offset of next pointer, we call fread and store the output in ptr_next[]
	char ptr_pid[4];	// When we calculate the offset of pid, we call fread and store the output in ptr_pid[]
	char ptr_next_next[4];	// When we calculate the offset of pid, we need to compare one more time, since the first pid is 0, 
					// the second pid is 1, they appears in the memory too often, therefore we go one more step and verify the next pid is 2.
	char ptr_pid_next[4];
	char *name = "swapper";		// This is pid=0 process, in Linux.
	char *name1 = "init";		// This is the pid=1 process, in Linux.


	/* Compute the offset of the process name */
	offset_of_name = get_offset_of_name(dumpfile, ptr, name);
	printf("Offset of process name is: 0x%lx\n", offset_of_name);

	/* Compute the offset of the next pointer */
	offset_of_next = get_offset_of_next(dumpfile, ptr_next, ptr, name1);
	printf("Offset of next pointer is: 0x%lx\n", offset_of_next);

	/* Compute the offset of the pid */
	offset_of_pid = get_offset_of_pid(dumpfile, ptr_next, ptr_pid, ptr_next_next, ptr_pid_next);
	printf("Offset of pid is: 0x%lx\n", offset_of_pid);
}

void print_processes(char *dumpfile2)
{
	FILE *ptr_dumpfile;
	unsigned char ptr[4096];
	unsigned long ptr_next[1];
	unsigned long ptr_pid[1];
	unsigned long print_counter = 0;
	ptr_dumpfile = fopen(dumpfile2,"rb");
	if (!ptr_dumpfile) {
		printf("Unable to open dump file!\n");
		exit(1);
    }

	printf("PID PROCESS_NAME\n");
	fseek(ptr_dumpfile, init_task, SEEK_SET);
//	printf("%lx\n",init_task+offset_of_next);
	while(1)
	{
		unsigned long ptr_mark=ftell(ptr_dumpfile);
		fseek(ptr_dumpfile, ptr_mark + offset_of_pid, SEEK_SET);
        fread(ptr_pid, 4, 1, ptr_dumpfile);
		*ptr_pid = *ptr_pid & 0xffffffff;
		printf("%ld ",*ptr_pid);
		fseek(ptr_dumpfile, ptr_mark + offset_of_name, SEEK_SET);
		fread(ptr, 4096, 1, ptr_dumpfile);
		printf("%s\n",ptr);
		fseek(ptr_dumpfile, ptr_mark + offset_of_next, SEEK_SET);
        fread(ptr_next, 4, 1, ptr_dumpfile);
		*ptr_next = *ptr_next & 0xffffffff;
//		printf(" %lx\n",(*ptr_next));
		if( *ptr_next == (init_task + offset_of_next + 0xc0000000) )
			break;
		fseek(ptr_dumpfile, *ptr_next - 0xc0000000 - offset_of_next, SEEK_SET);
		print_counter++;
	}
	printf("Total number of processes: %ld\n", print_counter);
	fclose(ptr_dumpfile);
}
