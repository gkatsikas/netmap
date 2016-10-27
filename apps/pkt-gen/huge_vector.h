/*
 * Copyright (C) 2015 Georgios Katsikas - KTH Royal Institute of Technology. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * $FreeBSD$
 * $Id: huge_vector.h
 *
 * A simple API definition of a huge vector with generic data container.
 * Used by pkt-gen to allocate main memory that can host pcap files.
 *
 */

#ifndef _HUGE_VECTOR_H__
#define _HUGE_VECTOR_H__

#include <stdint.h>

#define SUCCESS  0
#define FAILURE -1

#define DEF_SIZE 10000000

typedef uint64_t vector_size_t;

typedef struct huge_vector_ {
	void**   data;
	vector_size_t  rows;
	vector_size_t  count;
	unsigned short columns;
} huge_vector;

int   huge_vector_init       (huge_vector*, vector_size_t, unsigned short);
int   huge_vector_count      (huge_vector);
int   huge_vector_entries_no (huge_vector);
int   huge_vector_entry_size (huge_vector);
int   huge_vector_add        (huge_vector*, void*, unsigned short);
int   huge_vector_set        (huge_vector*, vector_size_t, void*);
void* huge_vector_get        (huge_vector,  vector_size_t);
int   huge_vector_delete     (huge_vector*, vector_size_t);
void  huge_vector_free       (huge_vector*);
void  huge_vector_print      (huge_vector);

#endif
