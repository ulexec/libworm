//
// Created by ulexec on 11/08/18.
//

#ifndef LIBX_LISTX_H
#define LIBX_LISTX_H

#include <stddef.h>

#endif //LIBX_LISTX_H

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

#define list_for_each(iter, head) for (iter = (head)->next; iter != (head); iter = iter->next)
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

static inline void init_list_head(struct list_head *list) {
    list->next = list;
    list->prev = list;
}

/* only for internal use*/
void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next) {
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

void __list_del(struct list_head *next, struct list_head *prev) {
    next->prev = prev;
    prev->next = next;
}

void list_del(struct list_head *entry) {
    __list_del(entry->next, entry->prev);
}

void list_add(struct list_head *new, struct list_head *head) {
    __list_add(new, head, head->next);
}

void list_add_tail(struct list_head *new, struct list_head *head) {
    __list_add(new, head->prev, head);
}
