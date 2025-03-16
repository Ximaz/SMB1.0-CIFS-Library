#ifndef __BUFFER_H_
    #define __BUFFER_H_

#ifndef BUFFER_SIZE
    #define BUFFER_SIZE 65535
#endif

typedef struct s_buffer
{
    char buffer[BUFFER_SIZE];
    int read;  /* The read head (aka cursor) */
    int write; /* The write head (aka cursor) */
} buffer_t;

/**
 * @brief Returns the current length of the data stored in the `buffer`.
 *
 * @param B The buffer pointer.
 * @return The number of bytes currently stored.
 */
#define BUFFER_LENGTH(B) \
    (((B)->write < (B)->read) * ((BUFFER_SIZE - (B)->read) + (B)->write) + \
    ((B)->write >= (B)->read) * ((B)->write - (B)->read))

/**
 * @brief Writes `data` of size `size` into the `buffer`.
 *
 * @param buffer The buffer to write data into.
 * @param data The data to write into the buffer.
 * @param size The size of the data.
 * @return 0 on success, -1 if the data can't fit in the `buffer`.
 */
int buffer_write(buffer_t *buffer, const void *data, int size);

/**
 * @brief Reads `read_size` bytes from `buffer`, stored into `output`.
 *
 * @param buffer The buffer to read data from.
 * @param output A memory chunk of size `read_size` to store read bytes.
 * @param read_size The number of bytes to read from `buffer`.
 * @return 0 on success, -1 if `buffer` is empty.
 */
int buffer_read(buffer_t *buffer, void *output, int read_size);

/**
 * @brief Clears the buffer.
 *
 * @param buffer The buffer to clear.
 */
void buffer_clear(buffer_t *buffer);

/**
 * @brief Move the read head of the `buffer` of `offset` bytes.
 *
 * @warning Be careful when dealing with negative offsets.
 *
 * @param buffer The buffer to seek the read head from.
 * @param offset The number of bytes to offset the read head.
 */
void buffer_seek(buffer_t *buffer, int offset);

#endif /* !__BUFFER_H_ */
