/*
 * Inspired by nss-mdns's buffer implementation.
 * Copyright 2004-2007 Lennart Poettering <mzaffzqaf (at) 0pointer (dot) de>
 */

#include "buffer.h"
#include <stdint.h>
#include <string.h>

static void *aligned_ptr(void *p)
{
    uintptr_t ptr = (uintptr_t)p;
    if (ptr % sizeof(void *))
        p += sizeof(void *) - (ptr % sizeof(void *));
    return p;
}

void buffer_init(struct buffer *buf, void *buffer, size_t buflen)
{
    // next always points to an aligned location.
    buf->next = aligned_ptr(buffer);
    // end is one past the buffer.
    buf->end = buffer + buflen;
}

void *buffer_alloc(struct buffer *buf, size_t size)
{
    // Zero-length allocations always succeed with non-NULL.
    if (size == 0)
        return buf; // Just a convenient non-NULL pointer.

    void *alloc_end = buf->next + size;
    if (alloc_end > buf->end)
        // No more memory in the buffer.
        return NULL;

    // We have enough space. Set up the next aligned pointer and return
    // the current one, zeroed.
    void *current = buf->next;
    buf->next = aligned_ptr(alloc_end);
    memset(current, 0, size);
    return current;
}

char *buffer_strdup(struct buffer *buf, const char *str)
{
    char *result = buffer_alloc(buf, strlen(str) + 1);
    if (result == NULL)
        return NULL;
    strcpy(result, str);
    return result;
}
