#include <stdio.h>
#include <stdlib.h>
#include "commands/smb_com_create_directory.h"
#include "debug_memory/debug_memory.h"

static inline void debug_smb_message_attr(const char *name, const void *attr,
size_t size, int is_array)
{
    printf("%s : ", name);
    if (is_array)
        printf("[");
    debug_memory(attr, size);
    if (is_array)
        printf("]");
    printf(" (%lu bytes)\n", size);
}

static void debug_smb_message(const smb_message_t msg)
{
    const smb_message_header_t *header = (const smb_message_header_t *)msg;

    printf("--- BEGIN SMB MESSAGE HEADER ---\n");
    debug_smb_message_attr("Protocol", (const void *)header->protocol, sizeof(UCHAR[4]), 0);
    debug_smb_message_attr("Command", (const void *)&(header->command), sizeof(SMB_COM), 0);
    debug_smb_message_attr("Status", (const void *)&(header->status), sizeof(SMB_ERROR), 0);
    debug_smb_message_attr("Flags", (const void *)&(header->flags), sizeof(SMB_FLAGS), 0);
    debug_smb_message_attr("Flags2", (const void *)&(header->flags2), sizeof(SMB_FLAGS2), 0);
    debug_smb_message_attr("PID", (const void *)&(header->pid_high), sizeof(USHORT), 0);
    debug_smb_message_attr("Security", (const void *)&(header->security_features), sizeof(UCHAR[8]), 0);
    debug_smb_message_attr("Reserved", (const void *)&(header->reserved), sizeof(USHORT), 0);
    debug_smb_message_attr("TID", (const void *)&(header->tid), sizeof(TID), 0);
    debug_smb_message_attr("PID", (const void *)&(header->pid_low), sizeof(USHORT), 0);
    debug_smb_message_attr("UID", (const void *)&(header->uid), sizeof(UID), 0);
    debug_smb_message_attr("MID", (const void *)&(header->mid), sizeof(MID), 0);
    printf("--- END SMB MESSAGE HEADER ---\n");
    printf("--- BEGIN SMB MESSAGE PARAMETER ---\n");
    debug_smb_message_attr("Words Count", (const void *)&(SMB_MSG_PARAMETER_WORDS_COUNT(msg)), sizeof(UCHAR), 0);
    debug_smb_message_attr("Words", (const void *)SMB_MSG_PARAMETER_WORDS(msg), sizeof(USHORT) * SMB_MSG_PARAMETER_WORDS_COUNT(msg), 1);
    printf("--- END SMB MESSAGE PARAMETER ---\n");
    printf("--- BEGIN SMB MESSAGE DATA ---\n");
    debug_smb_message_attr("Bytes Count", (const void *)&(SMB_MSG_DATA_BYTES_COUNT(msg)), sizeof(USHORT), 0);
    debug_smb_message_attr("Bytes", (const void *)SMB_MSG_DATA_BYTES(msg), sizeof(UCHAR) * SMB_MSG_DATA_BYTES_COUNT(msg), 1);
    printf("--- END SMB MESSAGE DATA ---\n");
    printf("--- BEGIN SMB MESSAGE RAW BYTES ---\n");
    debug_memory((const void *)msg, SMB_MSG_SIZE(msg));
    printf(" (%lu bytes)\n", SMB_MSG_SIZE(msg));
    printf("--- END SMB MESSAGE RAW BYTES ---\n");
}

int main(void)
{
    smb_message_t msg = smb_com_create_directory(1, 2, "MY PATH");

    debug_smb_message(msg);
    smb_message_dtor(msg);
    return 0;
}
