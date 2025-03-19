#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "smb_com_create.h"
#include <stdio.h>

smb_message_t smb_com_close_req(
    UID uid,
    FID fid,
    UTIME last_time_modified)
{
    smb_message_t msg = smb_message_ctor(0x03, 0);
    smb_message_header_t *header = (smb_message_header_t *)msg;

    if (NULL != msg)
    {
        header->command = SMB_COM_CLOSE;
        header->uid = uid;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 0) = fid;
        memcpy(SMB_MSG_PARAMETER_WORDS(msg) + 1, &last_time_modified, sizeof(UTIME));
    }
    return msg;
}
smb_message_t smb_com_close_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code)
{
    smb_message_t msg = smb_message_ctor(0, 0);
    smb_message_header_t *header = SMB_MSG_HEADER(msg);

    if (NULL != msg)
    {
        header->command = SMB_COM_CLOSE;
        header->status.error_class = error_class;
        header->status._reserved = 0;
        header->status.error_code = error_code;
    }
    return msg;
}
