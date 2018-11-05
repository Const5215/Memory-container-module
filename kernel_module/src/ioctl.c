//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2018
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
//     Core of Kernel Module for Processor Container
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
#include <linux/kthread.h>

#include <linux/list.h>

struct container_list_node {
    struct list_head list;
    int cid;
    struct list_head object_list_head, object_lock_head;
};

struct object_list_node {
    struct list_head list;
    char *object_location;
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

extern struct list_head *container_list_head, *container_map_head;

struct container_list_node* new_container_init(int new_cid);
struct container_map_node* new_mapping_init(int new_pid, int new_cid);
struct object_list_node* new_object_init(unsigned long new_offset);
struct object_lock_node* new_lock_init(unsigned long new_offset);
struct container_list_node* find_container_list(void);
struct container_map_node* find_container_map(void);
struct object_list_node* find_object_list(unsigned long offset);
struct object_lock_node* find_object_lock(unsigned long offset);
int find_cid(void);
int memory_container_mmap(struct file *filp, struct vm_area_struct *vma);
int memory_container_lock(struct memory_container_cmd __user *user_cmd);
int memory_container_unlock(struct memory_container_cmd __user *user_cmd);
int memory_container_create(struct memory_container_cmd __user *user_cmd);
int memory_container_delete(struct memory_container_cmd __user *user_cmd);
int memory_container_free(struct memory_container_cmd __user *user_cmd);

struct container_list_node* new_container_init(int new_cid) {
    struct container_list_node* new_container_node;
    new_container_node = (struct container_list_node*) kcalloc(1, sizeof(struct container_list_node), GFP_KERNEL);
    new_container_node->cid = new_cid;
    INIT_LIST_HEAD(&new_container_node->object_list_head);
    INIT_LIST_HEAD(&new_container_node->object_lock_head);
    list_add_tail(&new_container_node->list, container_list_head);
    return new_container_node;
}

struct container_map_node* new_mapping_init(int new_pid, int new_cid) {
    struct container_map_node* new_map_node;
    new_map_node = (struct container_map_node*) kcalloc(1, sizeof(struct container_map_node), GFP_KERNEL);
    new_map_node->pid = new_pid;
    new_map_node->cid = new_cid;
    list_add_tail(&new_map_node->list, container_map_head);
    return new_map_node;
}

struct object_list_node* new_object_init(unsigned long new_offset) {
    struct list_head* object_list_head;
    struct object_list_node* new_object_node;
    object_list_head = &find_container_list()->object_list_head;
    new_object_node = (struct object_list_node*) kcalloc(1, sizeof(struct object_list_node), GFP_KERNEL);
    new_object_node->offset = new_offset;
    list_add_tail(&new_object_node->list, object_list_head);
    return new_object_node;
}

struct object_lock_node* new_lock_init(unsigned long new_offset) {
    struct list_head* object_lock_head;
    struct object_lock_node* new_lock_node;
    object_lock_head = &find_container_list()->object_lock_head;
    new_lock_node = (struct object_lock_node*) kcalloc(1, sizeof(struct object_lock_node), GFP_KERNEL);
    new_lock_node->offset = new_offset;
    mutex_init(&new_lock_node->lock);
    list_add_tail(&new_lock_node->list, object_lock_head);
    return new_lock_node;
}

struct container_list_node* find_container_list() {
    int target_cid = find_cid();
    struct list_head *container_list_ptr;
    struct container_list_node *container_list_entry;
    for (container_list_ptr = container_list_head->next; container_list_ptr != container_list_head; container_list_ptr = container_list_ptr->next) {
        container_list_entry = list_entry(container_list_ptr, struct container_list_node, list);
        if (container_list_entry->cid == target_cid) {
            return container_list_entry;
        }
    }
    //no corresponding container
    return NULL;
}

struct container_map_node* find_container_map() {
    struct list_head* container_map_ptr;
    struct container_map_node* container_map_entry;
    for (container_map_ptr = container_map_head->next; container_map_ptr != container_map_head; container_map_ptr = container_map_ptr->next) {
        container_map_entry = list_entry(container_map_ptr, struct container_map_node, list);
        if (container_map_entry->pid == current->pid) {
            return container_map_entry;
        }
    }
    return NULL;
}

struct object_list_node* find_object_list(unsigned long offset) {
    struct container_list_node *target_container_node;
    struct object_list_node *object_list_entry;
    struct list_head *object_list_ptr, *object_list_head;

    target_container_node = find_container_list();
    object_list_head = &target_container_node->object_list_head;
    for (object_list_ptr = object_list_head->next; object_list_ptr != object_list_head; object_list_ptr = object_list_ptr->next) {
        object_list_entry = list_entry(object_list_ptr, struct object_list_node, list);
        if (object_list_entry->offset == offset) {
            return object_list_entry;
        }
    }
    return NULL;
}

struct object_lock_node* find_object_lock(unsigned long offset) {
    struct container_list_node *target_container_node;
    struct object_lock_node *object_lock_entry;
    struct list_head *object_lock_ptr, *object_lock_head;

    target_container_node = find_container_list();
    object_lock_head = &target_container_node->object_lock_head;
    for (object_lock_ptr = object_lock_head->next; object_lock_ptr != object_lock_head; object_lock_ptr = object_lock_ptr->next) {
        object_lock_entry = list_entry(object_lock_ptr, struct object_lock_node, list);
        if (object_lock_entry->offset == offset) {
            return object_lock_entry;
        }
    }
    return NULL;
}

int find_cid() {
    struct container_map_node* target_container_map;
    target_container_map = find_container_map();
    if (find_container_map() != NULL) {
        return target_container_map->cid;
    }
    else {
        //no register
        return -1;
    }
}

int memory_container_mmap(struct file *filp, struct vm_area_struct *vma) {
    struct object_list_node *target_object_node;
    unsigned long pfn_start;

    target_object_node = find_object_list(vma->vm_pgoff);
    if (target_object_node == NULL) {
        //offset invalid
        target_object_node = new_object_init(vma->vm_pgoff);
        //printk("Offset invalid at:%lu\n", vma->vm_pgoff);
        //return 0;
    }
    if (target_object_node->object_location == NULL) {
        //object location invalid, register new one
        target_object_node->object_location = (char *) kcalloc(1, (vma->vm_end - vma->vm_start)*sizeof(char), GFP_KERNEL);
    }
    //else {
        //printk("existing area found:%lu\n", vma->vm_pgoff);
    //}
    pfn_start = virt_to_phys(target_object_node->object_location) >> PAGE_SHIFT;
    remap_pfn_range(vma, vma->vm_start, pfn_start, vma->vm_end - vma->vm_start, vma->vm_page_prot);
    //printk("mapping:%dsize:%d\n",target_object_node->offset,vma->vm_end - vma->vm_start);
    return 0;
}


int memory_container_lock(struct memory_container_cmd __user *user_cmd) {
    __u64 user_cmd_oid;
    struct object_lock_node *target_lock_node;

    copy_from_user(&user_cmd_oid, &(user_cmd->oid), sizeof(__u64));
    target_lock_node = find_object_lock(user_cmd_oid);
    if (target_lock_node == NULL) {
        //offset invalid, register new one
        target_lock_node = new_lock_init(user_cmd_oid);
    }
    printk("locking:%lu\n",target_lock_node->offset);
    mutex_lock(&target_lock_node->lock);
    return 0;
}


int memory_container_unlock(struct memory_container_cmd __user *user_cmd) {
    __u64 user_cmd_oid;
    struct object_lock_node *target_lock_node;

    copy_from_user(&user_cmd_oid, &(user_cmd->oid), sizeof(__u64));
    target_lock_node = find_object_lock(user_cmd_oid);
    if (target_lock_node == NULL) {
        //offset invalid
        return 0;
    }
    printk("unlocking:%lu\n",target_lock_node->offset);
    mutex_unlock(&target_lock_node->lock);
    return 0;
}

int memory_container_delete(struct memory_container_cmd __user *user_cmd) {
    struct container_map_node* target_container_map;
    target_container_map = find_container_map();
    if (target_container_map != NULL) {
        list_del(&target_container_map->list);
        kfree(target_container_map);
    }
    return 0;
}

int memory_container_create(struct memory_container_cmd __user *user_cmd) {
    __u64 user_cmd_cid;
    struct container_map_node* target_container_map;

    copy_from_user(&user_cmd_cid, &(user_cmd->cid), sizeof(__u64));
    target_container_map = find_container_map();
    if (find_container_list() == NULL) {
        new_container_init(user_cmd_cid);
    }
    if (target_container_map == NULL) {    
        new_mapping_init(current->pid, user_cmd_cid);
    }
    else {
        target_container_map->cid = user_cmd_cid;
    }
    return 0;
}

int memory_container_free(struct memory_container_cmd __user *user_cmd) {
    __u64 user_cmd_oid;
    struct object_list_node *target_object_node;

    copy_from_user(&user_cmd_oid, &(user_cmd->oid), sizeof(__u64));
    target_object_node = find_object_list(user_cmd_oid);
    if (target_object_node == NULL) {
        return 0;
    }
    kfree(target_object_node->object_location);
    target_object_node->object_location = NULL;
    printk("freeing:%llu\n", user_cmd_oid);
    return 0;
}


/**
 * control function that receive the command in user space and pass arguments to
 * corresponding functions.
 */
int memory_container_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    switch (cmd)
    {
    case MCONTAINER_IOCTL_CREATE:
        return memory_container_create((void __user *)arg);
    case MCONTAINER_IOCTL_DELETE:
        return memory_container_delete((void __user *)arg);
    case MCONTAINER_IOCTL_LOCK:
        return memory_container_lock((void __user *)arg);
    case MCONTAINER_IOCTL_UNLOCK:
        return memory_container_unlock((void __user *)arg);
    case MCONTAINER_IOCTL_FREE:
        return memory_container_free((void __user *)arg);
    default:
        return -ENOTTY;
    }
}
