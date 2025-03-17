#include <string.h>
#include <stdlib.h>
#include "smb_com_create_directory.h"

smb_message_t smb_com_create_directory_req(
    UID uid,
    TID tid,
    const char *pathname)
{
    size_t pathname_len = strlen(pathname);
    smb_message_t msg = smb_message_ctor(0, 1 + pathname_len + 1);
    smb_message_header_t *header = (smb_message_header_t *)msg;

    if (NULL != msg)
    {
        header->command = SMB_COM_CREATE_DIRECTORY;
        header->tid = tid;
        header->uid = uid;
        *(SMB_MSG_DATA_BYTES(msg) + 0) = SMB_STRING;
        strncpy(SMB_MSG_DATA_BYTES(msg) + 1, pathname, pathname_len);
        /* The bytes array must include the null byte to end the string. */
        *(SMB_MSG_DATA_BYTES(msg) + 1 + pathname_len) = 0;
    }
    return msg;
}

smb_message_t smb_com_create_directory_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code)
{
    smb_message_t msg = smb_message_ctor(0, 0);
    smb_message_header_t *header = SMB_MSG_HEADER(msg);

    if (NULL != msg)
    {
        header->command = SMB_COM_CREATE_DIRECTORY;
        header->status.error_class = error_class;
        header->status._reserved = 0;
        header->status.error_code = error_code;
    }
    return msg;
}
