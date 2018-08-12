//
// Created by ulexec on 11/08/18.
//

#ifndef LIBX_LISTX_H
#define LIBX_LISTX_H

#include <stddef.h>

#define list_for_each(iter, head) for (iter = (head)->next; iter != (head); iter = iter->next)
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})


struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

void init_list_head(struct list_head *);
void __list_add(struct list_head *, struct list_head *, struct list_head *);
void __list_del(struct list_head *, struct list_head *);
void list_del(struct list_head *);
void list_add(struct list_head *, struct list_head *);
void list_add_tail(struct list_head *, struct list_head *);

#endif //LIBX_LISTX_H
