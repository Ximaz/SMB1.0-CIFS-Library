/**
 * This source code file exports function to deal with basic buffer operations
 * (read, write, clear and seek).
 */

#include <stdlib.h>
#include <string.h>
#include "buffer.h"

int buffer_write(buffer_t *buffer, const void *data, int size)
{
    int first_chunk = 0;

    if (size > (BUFFER_SIZE - BUFFER_LENGTH(buffer)))
        return -1;
    first_chunk = BUFFER_SIZE - buffer->write;
    if (size <= first_chunk)
        memcpy(buffer->buffer + buffer->write, data, size);
    else {
        memcpy(buffer->buffer + buffer->write, data, first_chunk);
        memcpy(buffer->buffer, (char *) data + first_chunk,
            size - first_chunk);
    }
    buffer->write = (buffer->write + size) % BUFFER_SIZE;
    return 0;
}

int buffer_read(buffer_t *buffer, void *output, int read_size)
{
    int buffer_length = BUFFER_LENGTH(buffer);
    int first_chunk = 0;

    if (0 == buffer_length)
        return -1;
    if (read_size > buffer_length)
        read_size = buffer_length;
    first_chunk = BUFFER_SIZE - buffer->read;
    if (read_size <= first_chunk)
        memcpy(output, buffer->buffer + buffer->read, read_size);
    else {
        memcpy(output, buffer->buffer + buffer->read,
            BUFFER_SIZE - buffer->read);
        memcpy((char *) output + first_chunk, buffer->buffer,
            read_size - first_chunk);
    }
    buffer->read = (buffer->read + read_size) % BUFFER_SIZE;
    return 0;
}

void buffer_clear(buffer_t *buffer)
{
    memset(buffer->buffer, 0, BUFFER_SIZE);
    buffer->read = 0;
    buffer->write = 0;
}

void buffer_seek(buffer_t *buffer, int offset)
{
    buffer->read = (buffer->read + offset) % BUFFER_SIZE;
}
