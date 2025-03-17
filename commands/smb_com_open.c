#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "smb_com_open.h"
#include <stdio.h>

smb_message_t smb_com_open_req(
    UID uid,
    TID tid,
    const char *pathname,
    smb_flags_t flags,
    smb_access_mode_t access_mode,
    smb_ext_file_attr_t search_attribute)
{
    size_t pathname_len = strlen(pathname);
    smb_message_t msg = smb_message_ctor(2, 1 + pathname_len + 1);
    smb_message_header_t *header = (smb_message_header_t *)msg;

    if (NULL != msg)
    {
        header->command = SMB_COM_OPEN;
        header->flags = flags;
        header->tid = tid;
        header->uid = uid;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 0) = access_mode;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 1) = search_attribute;
        *(SMB_MSG_DATA_BYTES(msg) + 0) = SMB_STRING;
        strncpy(SMB_MSG_DATA_BYTES(msg) + 1, pathname, pathname_len);
        /* The bytes array must include the null byte to end the string. */
        *(SMB_MSG_DATA_BYTES(msg) + 1 + pathname_len) = 0;
    }
    return msg;
}
smb_message_t smb_com_open_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code,
    const smb_com_open_file_t *file_handle)
{
    smb_message_t msg = smb_message_ctor(0x07, 0);
    smb_message_header_t *header = SMB_MSG_HEADER(msg);

    if (NULL != msg)
    {
        header->command = SMB_COM_OPEN;
        memcpy(SMB_MSG_PARAMETER_WORDS(msg), file_handle, sizeof(smb_com_open_file_t));
        header->status.error_class = error_class;
        header->status._reserved = 0;
        header->status.error_code = error_code;
    }
    return msg;
}
