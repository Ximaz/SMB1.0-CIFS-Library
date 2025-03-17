#include <stdio.h>
#include "smb_cifs.h"
#include "debug_memory/debug_memory.h"

static inline void debug_smb_message_attr(
    const char *name,
    const void *attr,
    size_t size,
    int is_array)
{
    printf("%s : ", name);
    if (is_array)
        printf("[");
    debug_memory(attr, size);
    if (is_array)
        printf("]");
    printf(" (%lu bytes)\n", size);
}

void debug_smb_message(const smb_message_t msg)
{
    const smb_message_header_t *header = (const smb_message_header_t *)msg;

    debug_smb_message_attr("Header.Protocol", (const void *)header->protocol, sizeof(UCHAR[4]), 0);
    debug_smb_message_attr("Header.Command", (const void *)&(header->command), sizeof(SMB_COM), 0);
    debug_smb_message_attr("Header.Status", (const void *)&(header->status), sizeof(SMB_ERROR), 0);
    debug_smb_message_attr("Header.Flags", (const void *)&(header->flags), sizeof(SMB_FLAGS), 0);
    debug_smb_message_attr("Header.Flags2", (const void *)&(header->flags2), sizeof(SMB_FLAGS2), 0);
    debug_smb_message_attr("Header.PIDHigh", (const void *)&(header->pid_high), sizeof(USHORT), 0);
    debug_smb_message_attr("Header.Security", (const void *)&(header->security_features), sizeof(UCHAR[8]), 0);
    debug_smb_message_attr("Header.Reserved", (const void *)&(header->reserved), sizeof(USHORT), 0);
    debug_smb_message_attr("Header.TID", (const void *)&(header->tid), sizeof(TID), 0);
    debug_smb_message_attr("Header.PIDLow", (const void *)&(header->pid_low), sizeof(USHORT), 0);
    debug_smb_message_attr("Header.UID", (const void *)&(header->uid), sizeof(UID), 0);
    debug_smb_message_attr("Header.MID", (const void *)&(header->mid), sizeof(MID), 0);
    debug_smb_message_attr("Parameter.WordsCount", (const void *)&(SMB_MSG_PARAMETER_WORDS_COUNT(msg)), sizeof(UCHAR), 0);
    debug_smb_message_attr("Parameter.Words", (const void *)SMB_MSG_PARAMETER_WORDS(msg), sizeof(USHORT) * SMB_MSG_PARAMETER_WORDS_COUNT(msg), 1);
    debug_smb_message_attr("Data.BytesCount", (const void *)&(SMB_MSG_DATA_BYTES_COUNT(msg)), sizeof(USHORT), 0);
    debug_smb_message_attr("Data.Bytes", (const void *)SMB_MSG_DATA_BYTES(msg), sizeof(UCHAR) * SMB_MSG_DATA_BYTES_COUNT(msg), 1);
    printf("Raw bytes : ");
    debug_memory((const void *)msg, SMB_MSG_SIZE(msg));
    printf(" (%lu bytes)\n", SMB_MSG_SIZE(msg));
}