#include <string.h>
#include <stdlib.h>
#include "smb_com_create_directory.h"
#include "../debug_memory/debug_memory.h"

smb_message_t smb_com_create_directory(
    UID uid,
    TID tid,
    const char *pathname)
{
    size_t pathname_len = strlen(pathname);
    smb_message_t msg = smb_message_ctor(0, pathname_len + 1);
    smb_message_header_t *header = (smb_message_header_t *)msg;

    header->command = SMB_COM_CREATE_DIRECTORY;
    header->tid = tid;
    header->uid = uid;
    *(SMB_MSG_DATA_BYTES(msg) + 0) = SMB_STRING;
    strncpy(SMB_MSG_DATA_BYTES(msg) + 1, pathname, pathname_len);
    return msg;
}
