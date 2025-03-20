#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "smb_com_rename.h"
#include <stdio.h>

smb_message_t smb_com_rename_req(
    UID uid,
    TID tid,
    const char *old_filename,
    const char *new_filename,
    smb_file_attributes_t search_attributes,
    int match_long_filenames)
{
    size_t old_filename_len = strlen(old_filename);
    size_t new_filename_len = strlen(new_filename);
    smb_message_t msg = smb_message_ctor(
        0x01,
        4 + old_filename_len + new_filename_len);
    smb_message_header_t *header = (smb_message_header_t *)msg;

    if (NULL != msg)
    {
        header->command = SMB_COM_RENAME;
        header->tid = tid;
        header->uid = uid;
        /* Branchless condition */
        header->flags2 = SMB_FLAGS2_LONG_NAMES * match_long_filenames;
        *(SMB_MSG_PARAMETER_WORDS(msg) + 0) = search_attributes;
        *(SMB_MSG_DATA_BYTES(msg) + 0) = SMB_STRING;
        strncpy(SMB_MSG_DATA_BYTES(msg) + 1, old_filename, old_filename_len);
        /* The bytes array must include the null byte to end the string. */
        *(SMB_MSG_DATA_BYTES(msg) + 1 + old_filename_len) = 0;
        *(SMB_MSG_DATA_BYTES(msg) + 2 + old_filename_len) = SMB_STRING;
        strncpy(SMB_MSG_DATA_BYTES(msg) + 3 + old_filename_len, new_filename,
                new_filename_len);
        /* The bytes array must include the null byte to end the string. */
        *(SMB_MSG_DATA_BYTES(msg) + 3 + old_filename_len +
          new_filename_len) = 0;
    }
    return msg;
}

smb_message_t smb_com_rename_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code)
{
    smb_message_t msg = smb_message_ctor(0x01, 0);
    smb_message_header_t *header = SMB_MSG_HEADER(msg);

    if (NULL != msg)
    {
        header->command = SMB_COM_RENAME;
        header->status.error_class = error_class;
        header->status._reserved = 0;
        header->status.error_code = error_code;
    }
    return msg;
}
