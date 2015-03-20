/*
 * task.h:  This file defines the partial task structure.
 * Copyright (c) 2015, Jidong Xiao (jidong.xiao@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 *
 */

struct hl_task_struct
{
    long pid;
    const char *proc_name;
    long next;   
};

/* Since we can determine the offset of process name, 
   but are not sure where is the start address of the task_struct, 
   we use process name as the base address. i.e., pid here means the offset from name to pid, 
   i.e., (offset of pid - offset of name) 
   Similarly, next here means the offset from name to next,
   i.e., (offset of next - offset of name) 
   Apparently, name here should be zero. */
struct hl_task_struct_offsets
{
    long pid;
    long name;
    long next;   
};
