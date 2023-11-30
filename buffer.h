/*
 * Inspired by nss-mdns's buffer implementation.
 * Copyright 2004-2007 Lennart Poettering <mzaffzqaf (at) 0pointer (dot) de>
 */

#ifndef BUFFER_H_
#define BUFFER_H_

#include <stdlib.h>

// Simple buffer allocator.
struct buffer
{
    void *next;
    void *end;
};

// Sets up a buffer.
void buffer_init(struct buffer *buf, void *buffer, size_t buflen);

// Allocates a zeroed, aligned chunk of memory of a given size from the buffer
// manager.
// If there is insufficient space, returns NULL.
void *buffer_alloc(struct buffer *buf, size_t size);

// Duplicates a string into a newly allocated chunk of memory.
// If there is insufficient space, returns NULL.
char *buffer_strdup(struct buffer *buf, const char *str);

#endif
