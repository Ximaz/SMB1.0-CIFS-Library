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

#define BUFFER_LENGTH(B) \
    (((B)->write < (B)->read) * ((BUFFER_SIZE - (B)->read) + (B)->write) + \
    ((B)->write >= (B)->read) * ((B)->write - (B)->read))

#endif /* !__BUFFER_H_ */
