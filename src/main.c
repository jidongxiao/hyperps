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
void print_processes(FILE *dumpfile);

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: %s trusted_image monitored_image\n", argv[0]);
    } else {
        DPRINTF("project kick-off!\n");
        printf("==================Get Process Offset from the Trusted OS=======================\n");
        FILE* trusted_dumpfile = fopen(argv[1], "rb");
        if (!trusted_dumpfile) {
            printf("Unable to open dump file: %s\n", argv[1]);
            return -1;
        }
        get_offsets(trusted_dumpfile);  // Get the offset of pid, process name, and next pointer
        fclose(trusted_dumpfile);

        printf("==================Print Processes of the Monitoring OS=========================\n");
        FILE* monitored_dumpfile = fopen(argv[2], "rb");
        if (!monitored_dumpfile) {
            printf("Unable to open dump file: %s\n", argv[2]);
            return -1;
        }
        print_processes(monitored_dumpfile); // Print the process list of the monitoring Guest OS
        fclose(monitored_dumpfile);
    }
    return 0;
}

long get_offset_of_name(FILE * fd, char* target_name) 
{
    long read_counter = 0;
    long offset = -1;
    char* name_pos = NULL;
    char buffer[BUFFER_SIZE];

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

long get_offset_of_next(FILE* fd, char* process_1)
{
    long read_counter = 0;
    long ptr_mark = 0;
    long next_offset_of_task = -1;
    char buffer[BUFFER_SIZE];
    char ptr_next[4];

    fseek(fd, init_task, SEEK_SET);

    while (!feof(fd)) {
        // read another 4 bytes and assume it is a pointer
        fread(ptr_next, 4, 1, fd);
        ptr_mark = ftell(fd);

        //if the pointer points to the kernel space
        if (*((unsigned int*) ptr_next) > KERNEL_BASE) {
            next_offset_of_task = read_counter * 4;
            fseek(fd, *((unsigned int*)ptr_next) - KERNEL_BASE - next_offset_of_task, SEEK_SET);
            fread(buffer, BUFFER_SIZE, 1, fd);
            if ((void *)memmem(buffer, BUFFER_SIZE, process_1, strlen(process_1)) - (void *)buffer == offset_of_name) {
                printf("Yes we found the next process name\n");
                printf("Therefore, we assert that the offset of the next pointer is: 0x%lx\n", next_offset_of_task);
                break;
            }
        }

        read_counter++;
        fseek(fd, ptr_mark, SEEK_SET);	// We need to go back to the original location and continue our fread.
    }
    return next_offset_of_task;
}

long get_offset_of_pid (FILE *fd)
{
    long read_counter = 0;
    long pid_offset_of_task = -1;
    long ptr_mark = 0;
    // When we calculate the offset of next pointer, we call fread and store the output in ptr_next[]
    char ptr_next[4];
    // When we calculate the offset of pid, we call fread and store the output in ptr_pid[] 
    char ptr_pid[4];
    // When we calculate the offset of pid, we need to compare one more time, since the first pid is 0, 
    // the second pid is 1, they appears in the memory too often, therefore we go one more step and verify the next pid is 2.
    char ptr_next_next[4];
    char ptr_pid_next[4];

    /* read the value of next pointer */
    fseek(fd, init_task + offset_of_next, SEEK_SET);
    fread(ptr_next, 4, 1, fd);
    
    fseek(fd, init_task, SEEK_SET);

    while (!feof(fd)) {
        fread(ptr_pid, 4, 1, fd);
        ptr_mark = ftell(fd);
        if ((*(unsigned int*)ptr_pid) == 0) {
            pid_offset_of_task = read_counter * 4;
            //fseek(fd, *((unsigned long*)ptr_next) - KERNEL_BASE - offset_of_next + offset, SEEK_SET);
            fseek(fd, (*(unsigned int*)ptr_next) - KERNEL_BASE - offset_of_next + pid_offset_of_task, SEEK_SET);
            fread(ptr_pid, 4, 1, fd);

            if ((*(unsigned int*)ptr_pid) == 1) {
                fseek(fd, (*(unsigned int*)ptr_next) - KERNEL_BASE, SEEK_SET);
                fread(ptr_next_next, 4, 1, fd);
                fseek(fd, (*(unsigned int*)ptr_next_next) - KERNEL_BASE - offset_of_next + pid_offset_of_task, SEEK_SET);
                fread(ptr_pid_next, 4, 1, fd);

                if ((*(unsigned int*)ptr_pid_next) == 2) {
                    printf("Yes we found the next pid.\n");
                    printf("Therefore, we assert that the offset of the pid is: 0x%lx\n", pid_offset_of_task);
                    break;
                }
            }
        }
        read_counter++;
        fseek(fd, ptr_mark, SEEK_SET);	// We need to go back to the original location and continue our fread.
    }
    return pid_offset_of_task;
}

void get_offsets(FILE *dumpfile)
{
    char *name = "swapper";		// This is pid=0 process, in Linux.
    char *name1 = "init";		// This is the pid=1 process, in Linux.

    /* Compute the offset of the process name */
    offset_of_name = get_offset_of_name(dumpfile, name);
    printf("Offset of process name is: 0x%lx\n", offset_of_name);

    /* Compute the offset of the next pointer */
    offset_of_next = get_offset_of_next(dumpfile, name1);
    printf("Offset of next pointer is: 0x%lx\n", offset_of_next);

    /* Compute the offset of the pid */
    offset_of_pid = get_offset_of_pid(dumpfile);
    printf("Offset of pid is: 0x%lx\n", offset_of_pid);
}

void print_processes(FILE *fd)
{
    char ptr[BUFFER_SIZE];
    char ptr_next[4];
    char ptr_pid[4];
    int print_counter = 0;
    long ptr_mark = 0;
    
    printf("PID PROCESS_NAME\n");
    fseek(fd, init_task, SEEK_SET);

    while (1) {
        ptr_mark = ftell(fd);
        fseek(fd, ptr_mark + offset_of_pid, SEEK_SET);
        fread(ptr_pid, 4, 1, fd);
        //*ptr_pid = *ptr_pid & 0xffffffff;
        printf("%d ",*(unsigned int*)ptr_pid);

        fseek(fd, ptr_mark + offset_of_name, SEEK_SET);
        fread(ptr, BUFFER_SIZE, 1, fd);
        printf("%s\n",ptr);

        fseek(fd, ptr_mark + offset_of_next, SEEK_SET);
        fread(ptr_next, 4, 1, fd);
        //*ptr_next = *ptr_next & 0xffffffff;

        if( (*(unsigned int*)ptr_next) == (init_task + offset_of_next + KERNEL_BASE) )
            break;
        fseek(fd, (*(unsigned int*)ptr_next) - KERNEL_BASE - offset_of_next, SEEK_SET);
        print_counter++;
    }
    printf("Total number of processes: %d\n", print_counter);
}
