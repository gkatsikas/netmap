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
 * $Id: huge_vector.c
 *
 * Implementation of a huge vector that stores u_char arrays.
 * Appropriate for storing large sets (rows) of packets.
 * Used by pkt-gen to allocate main memory that can host pcap files.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "huge_vector.h"

/*
 * Preallocate a vector of arrays. The number of rows is 'rows' and the array size is
 * 'columns' bytes. Set contents to all zeros.
 */
int
huge_vector_init(huge_vector* v, vector_size_t rows, unsigned short columns)
{
	v->data = NULL;

	if ( (rows <= 0) || (columns == 0) ) {
		fprintf(stderr, "HugeVector: Vector's dimensions must be positive numbers\n");
		return FAILURE;
	}
	v->rows    = rows;
	v->columns = columns;

	// No elements currently
	v->count   = 0;

	// Pre-allocate
	// 1. Rows
	v->data = malloc( sizeof(void*) * v->rows );
	if ( !v->data ) {
		fprintf(stderr, "HugeVector: Error while allocating packets' vector\n");
		return FAILURE;
	}
	memset(v->data, '\0', sizeof(void*) * v->rows);

	// 2. Columns
	vector_size_t i;
	for ( i=0; i<rows; i++ ) {
		v->data[i] = malloc( columns * sizeof(u_char) );
		if ( !v->data[i] ) {
			fprintf(stderr, "HugeVector: Error while allocating packets' vector\n");
			return FAILURE;
		}
		memset(v->data[i], '\0', (columns * sizeof(u_char)));
	}

	//fprintf(stdout, "HugeVector: Allocated space for %lu packets of size %d bytes each\n",
	//	(unsigned long)v->rows, v->columns);

	return SUCCESS;
}

/*
 * Return the number of allocated indices
 */
int
huge_vector_count(huge_vector v)
{
	return v.count;
}

/*
 * Return the number of occupied indices
 */
int
huge_vector_entries_no(huge_vector v)
{
	return v.rows;
}

/*
 * Return the number of bytes per entry
 */
int
huge_vector_entry_size(huge_vector v)
{
	return v.columns;
}

/*
 * If the vector hasn't reached the memory limit, add an element at the end.
 * If the vector is full, re-allocate memory (twice the size of the cuurent)
 * and add the element afterwards.
 */
int
huge_vector_add(huge_vector* v, void* e, unsigned short len)
{
	if ( !v )
		return FAILURE;

	// Last slot exhausted
	if ( v->rows == v->count ) {
		v->rows *= 2;
		fprintf(stdout, "HugeVector: Reallocate vector with new size: %ju\n", v->rows);

		// Extend height
		v->data  = realloc(v->data, sizeof(void*) * v->rows);
		if ( !v->data ) {
			fprintf(stderr, "HugeVector: Error while re-allocating packets' vector\n");
			return FAILURE;
		}

		// Allocate horizontally only for the new rows
		vector_size_t i;
		for ( i=v->count ; i < v->rows ; i++ ) {
			v->data[i] = malloc( v->columns * sizeof(u_char) );
			if ( !v->data[i] ) {
				fprintf(stderr, "HugeVector: Error while re-allocating packets' vector\n");
				return FAILURE;
			}
			memset(v->data[i], '\0', (v->columns * sizeof(u_char)));
		}
	}

	// Memory copy (expensive but safe)
	memcpy(v->data[v->count], e, len);

	// A new element added
	v->count++;

	//fprintf(stdout, "HugeVector: Successfully pushed element %ld\n", v->count);

	return SUCCESS;
}

/*
 * If index is valid, set its value to 'e'
 */
int
huge_vector_set(huge_vector* v, vector_size_t index, void *e)
{
	if ( !v )
		return FAILURE;

	if ( index >= v->count )
		return FAILURE;
	v->data[index] = e;

	return SUCCESS;
}

/*
 * If index is valid, get its value
 */
void*
huge_vector_get(huge_vector v, vector_size_t index)
{
	if ( index >= v.count )
		return NULL;
	return v.data[index];
}

/*
 * If index is valid, delete its value and shift the successive elements to the left.
 * Not very well tested and not super-efficient because of the shifts.
 */
int
huge_vector_delete(huge_vector* v, vector_size_t index)
{
	if ( !v )
		return FAILURE;

	if ( index >= v->count ) {
		fprintf(stderr, "HugeVector: Deletion failed, invalid index %ld\n", index);
		return FAILURE;
	}

	// Start shifting elements to the right in order to replace the
	// element to be deleted. Then nullify the last position and
	// decrement the count.
	vector_size_t i;
	for ( i = index; i < (v->count-1); i++ )
		if ( v->data[i] && v->data[i+1] )
			v->data[i] = v->data[i+1];

	// The last element must be nullified
	v->data[v->count-1] = NULL;

	// Now safely update the size
	v->count--;

	//fprintf(stdout, "HugeVector: Successfully deleted element %ld\n", index);

	return SUCCESS;
}

/*
 * Release the memory of the entire vector (Rows x Columns)
 */
void
huge_vector_free(huge_vector* v)
{
	if ( !v )
		return;

	vector_size_t i;

	// If there are deleted elements, v->count is less than v->rows
	// but memory is allocate for v->rows!
	for ( i = 0; i < v->rows; i++ ) {
		if ( v->data[i] != NULL ) {
			free(v->data[i]);
			v->data[i] = NULL;
		}
	}
	free(v->data);
	v->data = NULL;

	//fprintf(stdout, "HugeVector: Successfully released %ld bytes of memory\n",
	//		(unsigned long)v->rows * v->columns * sizeof(u_char));
}

/*
 * Print the contents of the vector.
 * Ugly results if hosting e.g. packets.
 */
void
huge_vector_print(huge_vector v)
{
	vector_size_t i;
	for ( i = 0; i < v.count; i++ ) {
		if ( v.data[i] ) {
			fprintf(stdout, "%s\n", (u_char*)v.data[i]);
		}
	}
}
