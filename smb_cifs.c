#include <stdlib.h>
#include <string.h>
#include "smb_cifs.h"

static inline void bind_smb_message_parameter(
    smb_message_t msg,
    UCHAR parameter_words_count)
{
    smb_message_parameters_t *ptr = (smb_message_parameters_t *)(msg + sizeof(smb_message_header_t));

    ptr->words_count = parameter_words_count;
}

static inline void bind_smb_message_data(
    smb_message_t msg,
    USHORT data_bytes_count,
    UCHAR parameter_words_count)
{
    smb_message_data_t *ptr =
        (smb_message_data_t *)(msg + sizeof(smb_message_header_t) +
                               sizeof(UCHAR) + parameter_words_count * sizeof(USHORT));

    ptr->bytes_count = data_bytes_count;
}

smb_message_t smb_message_ctor(
    UCHAR parameter_words_count,
    USHORT data_bytes_count)
{
    size_t object_size = sizeof(smb_message_header_t) +
                         sizeof(UCHAR) + parameter_words_count * sizeof(USHORT) +
                         sizeof(USHORT) + data_bytes_count * sizeof(UCHAR);
    smb_message_t msg = (smb_message_t)malloc(object_size);

    if (NULL != msg)
    {
        bind_smb_message_parameter(msg, parameter_words_count);
        bind_smb_message_data(msg, data_bytes_count, parameter_words_count);
        memset(msg, 0, sizeof(smb_message_header_t));
        strncpy(msg, PROTOCOL, 4);
    }
    return msg;
}

smb_message_t smb_message_decode(const void *raw_bytes)
{
    smb_message_t msg = smb_message_ctor(
        SMB_MSG_PARAMETER_WORDS_COUNT(raw_bytes),
        SMB_MSG_DATA_BYTES_COUNT(raw_bytes));

    if (NULL != msg)
        memcpy(msg, (const char *) raw_bytes, SMB_MSG_SIZE(raw_bytes));
    return msg;
}

void smb_message_dtor(smb_message_t msg)
{
    free(msg);
}