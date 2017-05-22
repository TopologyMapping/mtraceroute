/* Copyright (c) 2016-2017, Rafael Almeida <rlca at dcc dot ufmg dot br>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of mtraceroute nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include "list.h"

struct list *list_create() {
    struct list *l = malloc(sizeof(*l));
    if (l == NULL) return NULL;

    l->first = NULL;
    l->last = NULL;
    l->count = 0;
    return l;
}

void list_destroy(struct list *l) {
    while (l->count > 0) list_pop(l);
    free(l);
}

int list_insert(struct list *l, void *data) {
    struct list_item *i = malloc(sizeof(*i));
    if (i == NULL) return -1;

    i->data = data;
    i->next = NULL;
    i->previous = NULL;

    if (l->count == 0){ // list is empty
        l->first = i;
    } else {
        i->previous = l->last;
        l->last->next = i;
    }

    l->last = i;
    l->count++;
    return 0;
}

// Remove the first item that is equal (cmp_fn) to cmp_data and returns the data
void *list_remove(struct list *l, const void *cmp_data,
                  int (*cmp_fn)(const void *, const void *)) {
    struct list_item *i;
    for (i = l->first; i != NULL; i = i->next) {
        void *data = i->data;
        if (cmp_fn(cmp_data, data) == 0) {
            if (i->previous == NULL) {
                l->first = i->next;
            } else {
                i->previous->next = i->next;
            }

            if (i->next == NULL) {
                l->last = i->previous;
            } else {
                i->next->previous = i->previous;
            }

            l->count--;
            free(i);
            return data;
        }
    }
    return NULL;
}

// Remove the first item and returns the data
void *list_pop(struct list *l) {
    if (l->count == 0) return NULL;
    struct list_item *i = l->first;
    void *data = i->data;

    if (i->next == NULL) {
        l->first = NULL;
        l->last = NULL;
    } else {
        i->next->previous = NULL;
        l->first = i->next;
    }

    l->count--;
    free(i);
    return data;
}

struct list_item *list_find(struct list *l, const void *cmp_data,
                            int (*cmp_fn)(const void *, const void *)) {
    struct list_item *i;
    for (i = l->first; i != NULL; i = i->next) {
        void *data = i->data;
        if (cmp_fn(cmp_data, data) == 0) {
            return i;
        }
    }
    return NULL;
}

int list_insert_unique(struct list *l, void *data,
                       int (*cmp_fn)(const void *, const void *)) {
    if (list_find(l, data, cmp_fn) != NULL) return -1;
    return list_insert(l, data);
}

// Execute a function for each item in the list
void list_fn(struct list *l, void (*fn)(const void *, int, int)) {
    int index = 0;
    struct list_item *i;
    for (i = l->first; i != NULL; i = i->next) {
        fn(i->data, index, l->count);
        index++;
    }
    return;
}
