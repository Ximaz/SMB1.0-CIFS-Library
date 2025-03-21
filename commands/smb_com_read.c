#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "smb_com_read.h"
#include <stdio.h>

smb_message_t smb_com_read_req(
    UID uid,
    FID fid,
    USHORT count_of_bytes_to_read,
    ULONG read_offset_in_bytes,
    USHORT estimate_of_remaning_bytes_to_be_read,
    int read_if_execute)
{
    smb_message_t msg = smb_message_ctor(0x05, 0);
    smb_message_header_t *header = (smb_message_header_t *)msg;

    if (NULL != msg)
    {
        header->command = SMB_COM_READ;
        header->uid = uid;
        /* Branchless condition */
        header->flags2 = read_if_execute * SMB_FLAGS2_READ_IF_EXECUTE;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 0) = fid;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 1) = count_of_bytes_to_read;
        memcpy(SMB_MSG_PARAMETER_WORDS(msg) + 2, &read_offset_in_bytes, sizeof(ULONG));
        *(SMB_MSG_PARAMETER_WORDS(msg) + 4) = estimate_of_remaning_bytes_to_be_read;
    }
    return msg;
}

smb_message_t smb_com_read_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code,
    USHORT count_of_bytes_returned,
    USHORT count_of_bytes_read,
    const UCHAR *bytes)
{
    smb_message_t msg = smb_message_ctor(0x05, 0x0003 + count_of_bytes_read);
    smb_message_header_t *header = SMB_MSG_HEADER(msg);

    if (NULL != msg)
    {
        header->command = SMB_COM_READ;
        header->status.error_class = error_class;
        header->status._reserved = 0;
        header->status.error_code = error_code;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 0) = count_of_bytes_returned;
        memset(SMB_MSG_PARAMETER_WORDS(msg) + 1, 0, 8);
        *(SMB_MSG_DATA_BYTES(msg) + 0) = DATA_BUFFER;
        memcpy(SMB_MSG_DATA_BYTES(msg) + 1, &count_of_bytes_read,
               sizeof(USHORT));
        memcpy(SMB_MSG_DATA_BYTES(msg) + 3, bytes,
               count_of_bytes_read * sizeof(UCHAR));
    }
    return msg;
}
