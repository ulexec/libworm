//
// Created by ulexec on 12/08/18.
//

#include "worm.h"

void init_list_head(struct list_head *list) {
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
    __list_del (entry->next, entry->prev);
}

void list_add(struct list_head *new, struct list_head *head) {
    __list_add (new, head, head->next);
}

void list_add_tail(struct list_head *new, struct list_head *head) {
    __list_add (new, head->prev, head);
}

int list_empty(const struct list_head *head) {
    return (head->next) == head;
}