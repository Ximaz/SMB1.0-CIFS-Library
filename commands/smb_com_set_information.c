#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "smb_com_set_information.h"
#include <stdio.h>

smb_message_t smb_com_set_information_req(
    UID uid,
    TID tid,
    const char *filename,
    smb_file_attributes_t file_attributes,
    UTIME last_write_time)
{
    size_t filename_len = strlen(filename);
    smb_message_t msg = smb_message_ctor(0x08, 1 + filename_len + 1);
    smb_message_header_t *header = (smb_message_header_t *)msg;

    if (NULL != msg)
    {
        header->command = SMB_COM_SET_INFORMATION;
        header->tid = tid;
        header->uid = uid;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 0) = file_attributes;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 1) = last_write_time;
        /* Reserved bytes */
        memset(SMB_MSG_PARAMETER_WORDS(msg) + 2, 0, 10);
        *(SMB_MSG_DATA_BYTES(msg) + 0) = SMB_STRING;
        strncpy(SMB_MSG_DATA_BYTES(msg) + 1, filename, filename_len);
        /* The bytes array must include the null byte to end the string. */
        *(SMB_MSG_DATA_BYTES(msg) + 1 + filename_len) = 0;
    }
    return msg;
}

smb_message_t smb_com_set_information_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code)
{
    smb_message_t msg = smb_message_ctor(0, 0);
    smb_message_header_t *header = SMB_MSG_HEADER(msg);

    if (NULL != msg)
    {
        header->command = SMB_COM_SET_INFORMATION;
        header->status.error_class = error_class;
        header->status._reserved = 0;
        header->status.error_code = error_code;
    }
    return msg;
}
