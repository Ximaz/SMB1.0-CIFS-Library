#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "smb_com_create.h"
#include <stdio.h>

smb_message_t smb_com_flush_req(
    UID uid,
    FID fid)
{
    smb_message_t msg = smb_message_ctor(0x01, 0);
    smb_message_header_t *header = (smb_message_header_t *)msg;

    if (NULL != msg)
    {
        header->command = SMB_COM_FLUSH;
        header->uid = uid;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 0) = fid;
    }
    return msg;
}

smb_message_t smb_com_flush_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code)
{
    smb_message_t msg = smb_message_ctor(0, 0);
    smb_message_header_t *header = SMB_MSG_HEADER(msg);

    if (NULL != msg)
    {
        header->command = SMB_COM_FLUSH;
        header->status.error_class = error_class;
        header->status._reserved = 0;
        header->status.error_code = error_code;
    }
    return msg;
}
