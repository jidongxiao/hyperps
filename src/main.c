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
#include <getopt.h>
#include "hyperps/debug.h"

#define BUFFER_SIZE 4096
#define KERNEL_BASE 0xC0000000

#ifndef DEBUG
#define DEBUG 0
#endif

const char *trusted_dump = NULL;
const char *monitored_dump = NULL;
unsigned long init_task=0x16753a0;

const char *proc_name0=NULL;
const char *proc_name1=NULL;
const char *proc_name2=NULL;

// Windows
//char *proc_name0="Idle";
//char *proc_name1="System";

// Linux
//char *proc_name0="swapper";
//char *proc_name1="init";

// Debug Purpose
//char *proc_name0="keventd";
//char *proc_name1="kapmd";
//char *proc_name1="kupdated";
//char *proc_name1="ksoftirqd";
//char *proc_name0="smss";
//char *proc_name1="csrss";

// FreeBSD
//char *proc_name0="kernel";
//char *proc_name1="audit";
//char *proc_name2="init";
//char *proc_name3="idle";
//char *proc_name0="g_event";
//char *proc_name1="g_up";
//char *proc_name2="g_down";

long offset_of_name0 = -1;
long offset_of_name0_align4 = -1;
long offset_of_name0_least4 = -1;
long offset_of_name1 = -1;
long proc_offset_of_next;
long offset_of_name;
long offset_of_next;
unsigned long offset_of_pid;

long offset_of_name_in_task = -1;
long offset_of_next_in_task = -1;
long value_of_next0 = -1;
long value_of_next1 = -1;

// Physical memory dump.
void get_offsets_in_pdump(FILE *dumpfile);
void print_processes_from_pdump(FILE *dumpfile);

// Virtual memory dump.
long get_offsets_in_vdump(FILE* fd);
long get_offsets_in_vdump_second_pass(FILE* fd);
void print_process_from_vdump(FILE *fd);

unsigned int bits = 32; // We support both 32bits and 64bits.

unsigned int is_linux = 0; // For linux 32bits os, we can have some optimizations, because kernel space starts from 0xc000 0000, therefore, we don't have to search from the begining.
unsigned int is_win = 0; // For win 32bits os, we can have some optimizations, because kernel space starts from 0x8000 0000, therefore, we don't have to search from the begining.

// FIXME: Currently we assume we are using virtual memory dump, rather then physical memory dump, but we should support physical memory dump in the future.
unsigned int is_phys_dump = 0;	

// We consider the linked list could be construted in two ways, either "next" points to "next", or "next" points to the start of the next structure.
unsigned int next_to_next = 1;	

// Only for some rare cases, we need a second pass, for example, for FreeBSD 8.4 32bits.
unsigned int second_pass = 0;	

// So far, we only know that Linux kernel 2.4 has such property, i.e., the task_struct is 4k-aligned.
unsigned int task_4k_align=0;   

// Counts how many processes are there in the system.
unsigned int print_counter = 0;	

static void help(void)
{
    const char *help_msg =
           "HyperLink version 1.0, Copyright (c) 2014 Jidong Xiao & Lei Lu\n"
           "usage: hyperlink [options] -o OS trusted_dumpfile_path monitored_dumpfile_path\n"
           "HyperLink memory forensic utility\n"
           "\n"
           "Command options and parameters:\n"
           "  '-d' indicates that the dump file is a virtual memory dump or a physical memory dump,\n"
           "    the parameter can be either 'virt' or 'phys'\n"
           "  '-h' shows this help message\n"
           "  '-l' indicates that the linked list in the operating system is the old type of the new type,\n"
           "    the parameter can be either 'old' or 'new'\n"
           "  '-o' indicates the operating system of the dump file\n"
           "  'trusted_dumpfile_path' is the path to the trusted dump file\n"
           "  'monitored_dumpfile_path' is the path to the monitored dump file\n"
           "\n";

    printf("%s\n", help_msg);
    exit(1);
}

void parse_options(int argc, char **argv)
{
    int c;
    
    for (;;) {
        c = getopt(argc, argv, "d:t:m:l:o:h");
        if (c == -1) {
            break;
        }
        switch (c) {
        case '?':
        case 'h':
            help();
            break;
        case 'd': 
            /* dump type: VA memory dump or PA memory dump. */
            printf("The dump type is %s\n", optarg);
            if (strcmp(optarg, "phys") == 0) {
                is_phys_dump = 1;
                printf("Okay, so we are dealing with physical memory dump.\n");
            } else if (strcmp(optarg, "virt") == 0) {
                is_phys_dump = 0;
                printf("Okay, so we are dealing with virtual memory dump.\n");
            } else {
                printf("The dump file has to be either virtual memory dump, or physical memory dump.\n");
                exit(1);
            }
            break;
        case 't':
            trusted_dump = optarg;
            break;
        case 'm':
            monitored_dump = optarg;
            break;
        case 'l':    // link type, next points the next or next points to the start of the next structure.
            printf("The link type is %s\n", optarg);
            if (strcmp(optarg, "old") == 0) {
                next_to_next = 0;
                printf("Okay, so we are dealing with old type of linked list.\n");
            } else if (strcmp(optarg, "new") == 0) {
                next_to_next = 1;
                printf("Okay, so we are dealing with new type of linked list.\n");
            } else {
                printf("The linked list has to be either old, i.e., next to start, or new, i.e., next to next.\n");
                exit(1);
            }
            break;
        case 'o':
            if (strcmp(optarg, "linux") == 0) {
                is_linux = 1;
                proc_name0 = "swapper";
                proc_name1 = "init";
                printf("Okay, so we are dealing with Linux operating system dump.\n");
            } else if (strcmp(optarg, "linux24") == 0) {
                is_linux = 1;
                proc_name0 = "swapper";
                proc_name1 = "init";
                task_4k_align = 1;
                next_to_next = 0;
                printf("Okay, so we are dealing with Linux 2.4 operating system dump.\n");
            } else if (strcmp(optarg, "win") == 0) {
                is_win = 1;
                proc_name0 = "Idle";
                proc_name1 = "System";
                printf("Okay, so we are dealing with Windows operating system dump.\n");
            } else if(strcmp(optarg, "win2000") == 0) {
                is_win = 1;
                proc_name0 = "System";
                proc_name1 = "smss";
                proc_name2 = "csrss";
                printf("Okay, so we are dealing with Windows operating system dump, older than win 2000.\n");
            } else if (strcmp(optarg, "freebsd") == 0) {
//                proc_name0="kernel";
//                proc_name0="audit";    // Note, this is an optimization, the first process is kernel, but there are too many "kernel" in the memory, which makes the program super slow.
//                proc_name0="init";
//                proc_name0="idle";
                proc_name0 = "g_event";
                proc_name1 = "g_up";
                proc_name2 = "g_down";
                next_to_next = 0;
                second_pass = 1;
                printf("Okay, so we are dealing with FreeBSD 8.x operating system dump.\n");
            } else if (strcmp(optarg, "freebsd92") == 0) {
                proc_name0 = "sctp_iterator";
                proc_name1 = "xpt_thrd";
                proc_name2 = "pagedaemon";
// The following actually works but they are just too slow, because in memory there are too many audit, too many init, too many idle.
//                proc_name0 = "audit";
//                proc_name1 = "init";
//                proc_name2 = "idle";

//                proc_name0 = "intr";
//                proc_name0 = "geom";
//                proc_name0 = "yarrow";

                next_to_next = 0;
                second_pass = 1;
                printf("Okay, so we are dealing with FreeBSD 9.x operating system dump.\n");
            } else {
                printf("Sorry, The operating system dump you typed is not supported.\n");
                exit(1);
            }
            break;
        }
    }

    trusted_dump = argv[optind];
    optind++;
    monitored_dump = argv[optind];
}

int main(int argc, char *argv[])
{
    parse_options(argc, argv);
    DPRINTF("project kick-off!\n");

    if ((trusted_dump == NULL) || (monitored_dump == NULL)) {
        help();
        return -1;
    }

    FILE* trusted_dumpfile = fopen(trusted_dump, "rb");

    if (!trusted_dumpfile) {
        printf("Unable to open dump file: %s\n", trusted_dump);
        return -1;
    }
    if (!is_phys_dump) {	
        /* VA memory dump */
        printf("==================Get Process Offset from the Trusted OS=======================\n");
        
        if (get_offsets_in_vdump(trusted_dumpfile) == -1) {	
        // We need to get the offset of the first process name, second process name, and the offset of the first next pointer.
            fclose(trusted_dumpfile);
            return -1;
        }
        fclose(trusted_dumpfile);
    
        printf("==================Print Processes of the Monitoring OS=========================\n");
        
        FILE* monitored_dumpfile = fopen(monitored_dump, "rb");
        if (!monitored_dumpfile) {
            printf("Unable to open dump file: %s\n", monitored_dump);
            return -1;
        }

	    print_process_from_vdump(trusted_dumpfile);
        fclose(trusted_dumpfile);
    } else {	
        /* PA memory dump */
        printf("==================Get Process Offset from the Trusted OS=======================\n");
        
        get_offsets_in_pdump(trusted_dumpfile);  // Get the offset of pid, process name, and next pointer
        fclose(trusted_dumpfile);
        
        printf("==================Print Processes of the Monitoring OS=========================\n");
        
        FILE* monitored_dumpfile = fopen(monitored_dump, "rb");
        if (!monitored_dumpfile) {
            printf("Unable to open dump file: %s\n", monitored_dump);
            return -1;
        }
        print_processes_from_pdump(monitored_dumpfile); // Print the process list of the monitoring Guest OS
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

void get_offsets_in_pdump(FILE *dumpfile)
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

    //FIXME: we should return something if we could not find the offsets, so as to let the main program know not try to print the process.
}

/* Return 1 if find the 'next' pointer offset and set it to global variable 'proc_offset_of_next' 
 * Return 0 if not
 */
int vdump_get_offsets_point_to_linkedlist(FILE *fd)
{
    long read_counter0 = 0;
    long read_counter1 = 0;
    long ptr_mark0 = 0;
    long ptr_mark1 = 0;
    long starting_addr = 0;
    char* name_pos0 = NULL;
    char* name_pos1 = NULL;
    char ptr_next[4];
    char buffer[BUFFER_SIZE];
    
    if (is_linux == 1) { // For Linux 32bits, we do have this optimization, because kernel space starts from 0xc000 0000.
        starting_addr = 0xc0000000;
        ptr_mark1 = starting_addr;
    }

    if (is_win == 1) { // For Win 32bits, we do have this optimization, because kernel space starts from 0x8000 0000.
        starting_addr = 0x80000000;
        ptr_mark1 = starting_addr;
    }

    fseek(fd, starting_addr, SEEK_SET);

    while (!feof(fd)) {
        /* read one page of contents and search for process name */
        fread(buffer, BUFFER_SIZE, 1, fd);
        ptr_mark0 = ftell(fd);

        // search for the name of first process, for Linux, it is "swapper", for Windows, it is "Idle".
        name_pos0 = (char*) memmem(buffer, BUFFER_SIZE, proc_name0, strlen(proc_name0));    
            
        if (name_pos0 != NULL) {    
        /* Find first process's name string */
            
            // offset (from the start of the dump file) of the name string.
            offset_of_name0 = name_pos0 - buffer + starting_addr + read_counter0 * BUFFER_SIZE; 
            printf("Address for the first process name is: 0x%lx\n", offset_of_name0);
            //continue;   // This line is crucial when we want to debug.
            
            /* Start from pos = 0 and search for second process name */
            fseek(fd, starting_addr, SEEK_SET);
            
            while (!feof(fd)) {
                fseek(fd, ptr_mark1, SEEK_SET); // go back and read the next BUFFER
                fread(buffer, BUFFER_SIZE, 1, fd);
                ptr_mark1 = ftell(fd);
                name_pos1 = (char*) memmem(buffer, BUFFER_SIZE, proc_name1, strlen(proc_name1));    // search for the name of the second process, for Linux, it is "init", for Windows, it is "System".
                
                if (name_pos1 != NULL) {
                /* Find second process's name string */
                    
                    // offset (from the start of the dump file) of the second process's name string.
                    offset_of_name1 = name_pos1 - buffer + starting_addr + read_counter1 * BUFFER_SIZE; 
                    printf("Address for the second process name is: 0x%lx\n", offset_of_name1);
                    
                    /* Search for the next pointer position.
                     * Ranging from (offset of first process name - 1 page) to (offset of first process name + 1 page)
                     * Find pointers in range points to the same offset of the second process name in memory
                     */
                    fseek(fd, offset_of_name0 - 0x400, SEEK_SET);

                    int i;
                    // assuming the "next" pointer is before or after the "name", but within 1 page distance.
                    for(i = 0; i < 512; i++) {
                        fread(ptr_next, 4, 1, fd);  // assume this is a pointer
//                      printf("when i is %d, we assume this is the next pointer: 0x%x  ", i, (*(unsigned int*)ptr_next));
//                      printf("And the next pointer of process 1 (right hand)  is at: 0x%lx\n", (offset_of_name1-0x400+i*4) );
                        if ((*(unsigned int*)ptr_next) == offset_of_name1-0x400+i*4) {
                            proc_offset_of_next = offset_of_name0+i*4-0x400;
                            printf("Now we found the offset of the next pointer of the first process is 0x%lx\n", offset_of_name0+i*4-0x400);
                            printf("And the address for the first process name is: 0x%lx\n", offset_of_name0);
                            printf("And the address for the second process name is: 0x%lx\n", offset_of_name1);
                            return 1;
                        }
                    }

                    fseek(fd, offset_of_name0 - 0x402, SEEK_SET);

                    // assuming the "next" pointer is before or after the "name", but within 1 page distance.
                    for(i = 0; i < 514; i++) {
                        fread(ptr_next, 4, 1, fd);  // assume this is a pointer
//                      printf("when i is %d, we assume this is the next pointer: 0x%x  ", i, (*(unsigned int*)ptr_next));
//                      printf("And the next pointer of process 1 (right hand)  is at: 0x%lx\n", (offset_of_name1-0x402+i*4) );
                        if ((*(unsigned int*)ptr_next) == offset_of_name1-0x402+i*4) {
                            proc_offset_of_next = offset_of_name0+i*4-0x402;
                            printf("Now we found the offset of the next pointer of the first process is 0x%lx\n", offset_of_name0+i*4-0x402);
                            printf("And the address for the first process name is: 0x%lx\n", offset_of_name0);
                            printf("And the address for the second process name is: 0x%lx\n", offset_of_name1);
                            return 1;
                        }
                    }
                }
                read_counter1++;
            }
            read_counter1=0;    // reset read_counter1;
            ptr_mark1 = starting_addr;    // reset ptr_mark1 when the inner loop ends, so it starts from 0 the next time we start the inner loop.
            // go back and read the next BUFFER
            // FIXME: This fseek clears feof flag, so when we really cannot find the process next pointer by the end of the memory dump file, our loop won't finish.
            fseek(fd, ptr_mark0, SEEK_SET);
        }
        read_counter0++;
    }
    return 0;
}

int vdump_get_offsets_point_to_task_struct(FILE *fd)
{
    long read_counter0 = 0;
    long read_counter1 = 0;
    long ptr_mark0 = 0;
    long ptr_mark1 = 0;
    long starting_addr = 0;
    char* name_pos0 = NULL;
    char* name_pos1 = NULL;
    char ptr_next[4];
    char buffer[BUFFER_SIZE];

    if (is_linux == 1) { // For Linux 32bits, we do have this optimization, because kernel space starts from 0xc0000000.
        starting_addr = 0xc0000000;
        ptr_mark1 = starting_addr;
    }

    if (is_win == 1) { // For Windows 32bits, we do have this optimization, because kernel space starts from 0x80000000.
        starting_addr = 0x80000000;
        ptr_mark1 = starting_addr;
    }

    fseek(fd, starting_addr, SEEK_SET);
    while (!feof(fd)) {
        /* read one page of contents and search for process name */
        fread(buffer, BUFFER_SIZE, 1, fd);
        ptr_mark0 = ftell(fd);

        // search for the name of first process, for Linux, it is "swapper", for Windows, it is "Idle"
        name_pos0 = (char*) memmem(buffer, BUFFER_SIZE, proc_name0, strlen(proc_name0));

        if (name_pos0 != NULL) {
        /*  Find first process's name string */

            // offset (from the start of the dump file) of the name string.
            offset_of_name0 = name_pos0 - buffer + starting_addr + read_counter0 * BUFFER_SIZE;

            // We need to clean the lower 4 bits, for Linux Kernel 2.4, the task_struct is 4K page align.
            offset_of_name0_align4 = offset_of_name0 & 0xfffff000;

            // We need to store the lower 4 bits
            offset_of_name0_least4 = offset_of_name0 & 0xfff;
            printf("Address for the first process's name is: 0x%lx\n", offset_of_name0);

            //Read from the begining
            fseek(fd, starting_addr, SEEK_SET);

            while (!feof(fd)) {
                /* Read one page */
                fseek(fd, ptr_mark1, SEEK_SET);
                fread(buffer, BUFFER_SIZE, 1, fd);
                ptr_mark1 = ftell(fd);

                // search for the name of the second process, for Linux, it is "init", for Windows, it is "System".
                name_pos1 = (char*) memmem(buffer, BUFFER_SIZE, proc_name1, strlen(proc_name1));

                if (name_pos1 != NULL) {
                /* Find the second process's name */

                    // offset (from the start of the dump file) of the second process's name string.
                    offset_of_name1 = name_pos1 - buffer + starting_addr + read_counter1 * BUFFER_SIZE;
                    printf("Address for the second process's name is: 0x%lx\n", offset_of_name1);
                    /* Align offset to 4K for the next read */
                    fseek(fd, offset_of_name0_align4, SEEK_SET);
                    int i;
                    /* Search for one page distance*/
                    for(i = 0; i < 1024; i++) {
                        // assume this is a pointer
                        fread(ptr_next, 4, 1, fd);

                        /* Check if there is any pointer points to 4K-aligned offset of the second process' name */
                        if ((*(unsigned int*) ptr_next) == (offset_of_name1 & 0xfffff000)) {
                            proc_offset_of_next = offset_of_name0_align4+i*4;
                            printf("Now we found the offset of the next pointer of the first process is 0x%lx\n", offset_of_name0_align4+i*4);
                            printf("And the address for the first process name is: 0x%lx\n", offset_of_name0);
                            printf("And the address for the second process name is: 0x%lx\n", offset_of_name1);
                            return 1;
                        }
                    }
                }
                /* If not found, read the next page*/
                read_counter1++;
            }
            read_counter1=0;  // reset read_counter1;
            ptr_mark1 = starting_addr;      // reset ptr_mark1 when the inner loop ends, so it starts from 0 the next time we start the inner loop.

            // go back and read the next BUFFER
            // FIXME: This fseek clears feof flag, so when we really cannot find the process next pointer by the end of the memory dump file, our loop won't finish.
            fseek(fd, ptr_mark0, SEEK_SET);
        }
        read_counter0++;
    }
    return 0;
}


long get_offsets_in_vdump(FILE* fd)
{
    long found_next = 0;

    if (next_to_next == 1) {
    /* When "next" points to the "next" pointer, rather than the start of the next structure, this is true for Linux Kernel 2.6 as well as for Windows 7. */
        found_next = vdump_get_offsets_point_to_linkedlist(fd);
    } else if (task_4k_align == 1) {
    /* When "next" points to the start of the next structure, and the task_struct is 4k-aligned, this is true for Linux Kernel 2.4. */
        found_next = vdump_get_offsets_point_to_task_struct(fd);
    }    

    if (found_next == 1) {
        return 0;
    } else {
        second_pass = 1;
        printf("===We need a second pass to get the offsets.===\n");
        if (get_offsets_in_vdump_second_pass(fd) == -1) {
            return -1;	// we could not find the offsets to construct the linked list
        } else {
            return 0;
        }
    }
    return -1;
}

long get_offsets_in_vdump_second_pass(FILE* fd)    // When "next" points to the start of the next structure, but the task_struct is _not_ 4k-aligned, this is true for FreeBSD 8.4.
{
    long read_counter0 = 0;
    long read_counter1 = 0;
    long ptr_mark0 = 0;
    long ptr_mark1 = 0;
    long ptr_mark2 = 0;
//    long next_offset_of_task = -1;
    char* name_pos0 = NULL;
    char* name_pos1 = NULL;
    char buffer[BUFFER_SIZE];
//    char ptr_pid0[4];
//    char ptr_pid1[4];
    char ptr_next[4];
    long found_next = 0;

    fseek(fd, 0, SEEK_SET);

    while (!feof(fd)) {
        fread(buffer, BUFFER_SIZE, 1, fd);
        ptr_mark0 = ftell(fd);
        name_pos0 = (char*) memmem(buffer, BUFFER_SIZE, proc_name0, strlen(proc_name0));    // search for the name of first process, for Linux, it is "swapper", for Windows, it is "Idle"
        if (name_pos0 != NULL) {    // now we got the first process's name string
            offset_of_name0 = name_pos0 - buffer + read_counter0 * BUFFER_SIZE;     // offset (from the start of the dump file) of the name string.
//            offset_of_name0_align4 = offset_of_name0 & 0xfffff000;  // We need to clean the lower 4 bits, for Linux Kernel 2.4, the task_struct is 4K page align.
//            offset_of_name0_least4 = offset_of_name0 & 0xfff;       // We need to store the lower 4 bits
//              printf("So the least 4 bits of offset_of_name0 is: 0x%lx\n", offset_of_name0_least4);
            printf("So the address for the first process's name is: 0x%lx\n", offset_of_name0);
//            printf("And the read_counter0 is: %d\n", read_counter0);
//            {//for debug only, remind to remove all the following lines.
//              read_counter0++;
//              fseek(fd, ptr_mark0, SEEK_SET);
//              continue;       // This line is crucial when we want to debug.
//            }
            fseek(fd, 0, SEEK_SET);
            while (!feof(fd)) {
                fseek(fd, ptr_mark1, SEEK_SET);     // go back and read the next BUFFER
                fread(buffer, BUFFER_SIZE, 1, fd);
                ptr_mark1 = ftell(fd);
                name_pos1 = (char*) memmem(buffer, BUFFER_SIZE, proc_name1, strlen(proc_name1));    // search for the name of the second process, for Linux, it is "init", for Windows, it is "System".
                if (name_pos1 != NULL) {    // now we also got the second process's name string
                    offset_of_name1 = name_pos1 - buffer + read_counter1 * BUFFER_SIZE;     // offset (from the start of the dump file) of the second process's name string.
                    if( (offset_of_name1 < offset_of_name0 - 4096) || (offset_of_name1 > offset_of_name0 + 4096) ) {   // FIXME: This is an optimization, based on my experience, for FreeBSD 32bits, the gap between offset_of_name0 and offset_of_name1 is usually less than 4096 bytes, but this might be wrong if we test more FreeBSD images.
                        read_counter1++;
                        continue;
                    }
                    printf("So the address for the second process's name is: 0x%lx\n", offset_of_name1);
//                    ptr_mark2=offset_of_name0-4096;
                    ptr_mark2=offset_of_name0-0x400;    // FIXME: we use hardcode here, based on our experience, the gap between next to name is usually less than 1024 bytes, which is 0x400.
//                    fseek(fd,offset_of_name0-4096,SEEK_SET);      // search the next pointer, let's go back 4096 bytes, and start from there.
//                    printf("We start searching from: 0x%lx\n", ptr_mark2);
                    int i;
//                    for(i=0;i<1024;i++){    // assuming the "next" pointer is before or after the "name", but within 1 page distance.
                    for(i=0;i<256;i++){    // assuming the "next" pointer is before or after the "name", but within 1 page distance.
                        fseek(fd, ptr_mark2, SEEK_SET);
                        fread(ptr_next, 4, 1, fd);  // assume this is a pointer
                        ptr_mark2 = ftell(fd);
//                        printf("when i is %d, we assume this is the next pointer: 0x%x\n", i, (*(unsigned int*)ptr_next));
//                        printf("So the least 4 bits of offset_of_name0 is: 0x%lx\n", offset_of_name0_least4);
//                        long debug_right = offset_of_name1-4096-offset_of_name0_least4 +i*4;
//                        printf("So the address for Windows process name 0 is: 0x%lx\n", offset_of_name0);
//                        printf("So the address for Windows process name 1 is: 0x%lx\n", offset_of_name1);
//                        printf("And the next pointer of process 1 (right hand)  is at: 0x%lx\n", debug_right);
                        if ( ((*(unsigned int*)ptr_next) >= (offset_of_name1 - 0x400)) && ((*(unsigned int*)ptr_next) < offset_of_name1) ){    // Our experience is next is always in front of name.
                            proc_offset_of_next = offset_of_name0 - 0x400 + i*4;
                            value_of_next0 = (*(unsigned int*)ptr_next);
                            printf("min is 0x%lx\n", offset_of_name1 - 0x400);
                            printf("value_of_next0 is 0x%lx\n", value_of_next0);
                            printf("max is 0x%lx\n", offset_of_name1 + 0x400);
                            offset_of_name_in_task = offset_of_name1 - value_of_next0;
                            if(proc_offset_of_next < (offset_of_name0 - offset_of_name_in_task)) // This does not make sense, i.e., when next is before the start of the structure.
                                continue;
                            offset_of_next_in_task = proc_offset_of_next - (offset_of_name0 - offset_of_name_in_task);
                            printf("offset_of_name_in_task is 0x%lx\n", offset_of_name_in_task);
                            printf("offset_of_next_in_task is 0x%lx\n", offset_of_next_in_task);
                            fseek(fd, value_of_next0+offset_of_next_in_task, SEEK_SET);
                            fread(ptr_next, 4, 1, fd);  // assume this is a pointer
                            value_of_next1 = (*(unsigned int*)ptr_next);
                            printf("value_of_next1 is 0x%lx\n", value_of_next1);
                            fseek(fd, value_of_next1+offset_of_name_in_task, SEEK_SET);
                            fread(buffer, strlen(proc_name2), 1, fd);
                            printf("the buffer we read in is %s\n", buffer);
                            printf("and proc_name2 is %s\n", proc_name2);
                            if( strstr(buffer, proc_name2) != NULL ){
                                found_next = 1;
                                printf("Now we found the offset of the next pointer of the first process is 0x%lx\n", proc_offset_of_next);
                                printf("And the address for the first process name is: 0x%lx\n", offset_of_name0);
                                printf("And the address for the second process name is: 0x%lx\n", offset_of_name1);
                                break; // jump out of the for loop
                            }
                        }
                    }
                    if (found_next == 1)
                        break;      // jump out of the inner while loop
                }
                read_counter1++;
            }
            read_counter1=0;        // reset read_counter1;
            ptr_mark1=0;    // reset ptr_mark1 when the inner loop ends, so it starts from 0 the next time we start the inner loop.
            fseek(fd, ptr_mark0, SEEK_SET); // go back and read the next BUFFER // FIXME: This fseek clears feof flag, so when we really cannot find the process next pointer by the end of the memory dump file, our loop won't finish.
            if (found_next == 1)
                break;      // jump out of the outer while loop
        }
        read_counter0++;
    }

    if(found_next == 1){
        offset_of_name_in_task = offset_of_name1 - value_of_next0;
        offset_of_next_in_task = proc_offset_of_next - (offset_of_name0 - offset_of_name_in_task);
        printf("offset_of_name_in_task is 0x%lx\n", offset_of_name_in_task);
        printf("offset_of_next_in_task is 0x%lx\n", offset_of_next_in_task);
        return 0;
    }else{
        printf("Sorry we could not find the offsets to construct the linked list!\n");
        return -1;      // we could not find the offsets to construct the linked list
    }
}

void print_process_from_vdump(FILE *fd)
{
    char ptr_next[4];
//    char ptr_name[40];
    char ptr_name[BUFFER_SIZE];
    long next_pointer_value;

//offset_of_name0=0xc36b623e;
//offset_of_name0_least4=0x23e;
//offset_of_name1=0xc36b423e;
//proc_offset_of_next=0xc36b609c;
//proc_offset_of_next=0xc0346050;

    fseek(fd, offset_of_name0, SEEK_SET);	// process 0, name pointer
    fread(ptr_name, BUFFER_SIZE, 1, fd);	// this should be the process name
    printf("Name of the process is %s\n",ptr_name);	// print process 0 name
    print_counter++;

    fseek(fd, offset_of_name1, SEEK_SET);	// process 0, name pointer
    fread(ptr_name, BUFFER_SIZE, 1, fd);	// this should be the process name
    printf("Name of the process is %s\n",ptr_name);	// print process 1 name
    print_counter++;

//    printf("proc_offset_of_next is 0x%lx\n", proc_offset_of_next);
//    printf("offset_of_name0_least4 is 0x%lx\n", offset_of_name0_least4);

    if(next_to_next == 1){	// When "next" points to the "next" pointer, rather than the start of the next structure, this is true for Linux Kernel 2.6 as well as for Windows 7.
        fseek(fd, proc_offset_of_next, SEEK_SET);	// process 0, next pointer
        fread(ptr_next, 4, 1, fd);	// assume this is a pointer
        next_pointer_value=(*(unsigned int*)ptr_next);
        while(1){
            fseek(fd, next_pointer_value, SEEK_SET);	// process 1, next pointer
            fread(ptr_next, 4, 1, fd);	// assume this is a pointer
            if( ((*(unsigned int*)ptr_next) == proc_offset_of_next) || ((*(unsigned int*)ptr_next) == 0) )	// If it points to the next pointer of the first process, we assume we have traversed all processes.
                break;
            next_pointer_value=(*(unsigned int*)ptr_next);
            fseek(fd, next_pointer_value-(proc_offset_of_next-offset_of_name0), SEEK_SET);	// process 2, next pointer
            fread(ptr_name, BUFFER_SIZE, 1, fd);	// this should be the process name
            if(strlen(ptr_name) > 0) 
                printf("Name of the process is %s\n",ptr_name);
            print_counter++;
        }
    }else{	// When "next" points to the start of the next structure, this is true for Linux Kernel 2.4 as well as FreeBSD 8.4.
        fseek(fd, proc_offset_of_next, SEEK_SET);	// process 0, next pointer
        fread(ptr_next, 4, 1, fd);	// assume this is a pointer
        next_pointer_value=(*(unsigned int*)ptr_next);
//        printf("Value of next pointer is 0x%lx\n", next_pointer_value);
        if(second_pass == 0){
            while(1){
                fseek(fd,( (next_pointer_value & 0xfffff000)+ (proc_offset_of_next & 0xfff) ), SEEK_SET);	// process 2, next pointer
                fread(ptr_next, 4, 1, fd);	// assume this is a pointer
                if( ((*(unsigned int*)ptr_next) == (proc_offset_of_next & 0xfffff000)) || ((*(unsigned int*)ptr_next) == 0) )	// If it points to the start address of the first process, we assume we have traversed all processes.
                    break;
                next_pointer_value=(*(unsigned int*)ptr_next);
//          fseek(fd, next_pointer_value-(proc_offset_of_next-offset_of_name0), SEEK_SET);	// process 2, next pointer
                fseek(fd, next_pointer_value+offset_of_name0_least4, SEEK_SET);	// process 2, next pointer
                fread(ptr_name, BUFFER_SIZE, 1, fd);	// this should be the process name
                if(strlen(ptr_name) > 0) 
                    printf("Name of the process is %s\n",ptr_name);
                print_counter++;
            }
        }else{
            while(1){
                fseek(fd,( next_pointer_value + offset_of_next_in_task ), SEEK_SET);	// process 2, next pointer
                fread(ptr_next, 4, 1, fd);	// assume this is a pointer
                if( (*(unsigned int*)ptr_next) == (proc_offset_of_next - offset_of_next_in_task) || ((*(unsigned int*)ptr_next) == 0) )	// If it points to the start address of the first process, we assume we have traversed all processes.
                    break;
                next_pointer_value=(*(unsigned int*)ptr_next);
//                printf("next_pointer_value is 0x%lx\n", next_pointer_value);
//          fseek(fd, next_pointer_value-(proc_offset_of_next-offset_of_name0), SEEK_SET);	// process 2, next pointer
                fseek(fd, next_pointer_value+offset_of_name_in_task, SEEK_SET);	// process 2, next pointer
                fread(ptr_name, BUFFER_SIZE, 1, fd);	// this should be the process name
                if(strlen(ptr_name) > 0) 
                    printf("Name of the process is %s\n", ptr_name);
                print_counter++;
            }
        }
    }
    printf("Total number of processes: %d\n", print_counter);

}

void print_processes_from_pdump(FILE *fd)
{
    char ptr[BUFFER_SIZE];
    char ptr_next[4];
    char ptr_pid[4];
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

