//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2016
//
////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
////////////////////////////////////////////////////////////////////////
//
//   Author:  Hung-Wei Tseng, Yu-Chia Liu
//
//   Description:
//     Core of Kernel Module for Memory Container
//
////////////////////////////////////////////////////////////////////////

#include "memory_container.h"

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/sched.h>

#include <linux/list.h>

extern struct miscdevice memory_container_dev;

struct container_list_node {
    struct list_head list;
    int cid;
    struct list_head object_list_head, object_lock_head;
};

struct object_list_node {
    struct list_head list;
    char* object_location;
    unsigned long offset, size;
};

struct object_lock_node {
    struct list_head list;
    struct mutex lock;
	unsigned long offset;
};

struct container_map_node {
    struct list_head list;
    int pid;
    int cid;
};

struct list_head *container_list_head, *container_map_head;

int memory_container_init(void)
{
    int ret;

    if ((ret = misc_register(&memory_container_dev)))
    {
        printk(KERN_ERR "Unable to register \"memory_container\" misc device\n");
        return ret;
    }

    container_list_head = (struct list_head*) kcalloc(1, sizeof(struct list_head), GFP_KERNEL);
    INIT_LIST_HEAD(container_list_head);
    container_map_head = (struct list_head*) kcalloc(1, sizeof(struct list_head), GFP_KERNEL);
    INIT_LIST_HEAD(container_map_head);

    printk(KERN_ERR "\"memory_container\" misc device installed\n");
    printk(KERN_ERR "\"memory_container\" version 0.1\n");
    return ret;
}


void memory_container_exit(void)
{
    struct list_head *ci, *tmpci;
    struct container_list_node *cptr;
    struct object_list_node *optr;
    struct object_lock_node *lptr;
    struct list_head *oi, *tmpoi, *o_list_head, *o_lock_head;
    struct list_head *mi, *tmpmi;
    struct container_map_node *mptr;
    list_for_each_safe(ci, tmpci, container_list_head) {
        cptr = list_entry(ci, struct container_list_node, list);
        o_list_head = &cptr->object_list_head;
        o_lock_head = &cptr->object_lock_head;
        if (o_list_head != NULL) {
            list_for_each_safe(oi, tmpoi, o_list_head) {
                optr = list_entry(oi, struct object_list_node, list);
                if (optr->object_location != NULL) {
                    kfree(optr->object_location);
                }
                list_del(oi);
                kfree(optr);
            }
        }
        if (o_lock_head != NULL) {
            list_for_each_safe(oi, tmpoi, o_lock_head) {
                lptr = list_entry(oi, struct object_lock_node, list);
                list_del(oi);
                kfree(lptr);
            }
        }
        list_del(ci);
        kfree(cptr);
    }
    list_for_each_safe(mi, tmpmi, container_map_head) {
        mptr = list_entry(mi, struct container_map_node, list);
        list_del(mi);
        kfree(mptr);
    } 
    misc_deregister(&memory_container_dev);
}
