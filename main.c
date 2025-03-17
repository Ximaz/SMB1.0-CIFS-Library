#include <stdio.h>
#include "smb_cifs_commands.h"
#include "debug_smb_message.h"

int main(void)
{
    // smb_message_t open = smb_com_open_req(1, 2, "MY PATH", 0, ACCESS_MODE_READWRITE | SHARING_MODE_DENY_ALL, ATTR_NORMAL);
    smb_com_open_file_t fh = {
        .fid = 1,
        .file_attrs = ATTR_NORMAL,
        .access_mode = ACCESS_MODE_READWRITE | SHARING_MODE_DENY_ALL,
        .file_size = 1024 * 1024,
        .last_modified = 0x000011AA
    };
    smb_message_t resp = smb_com_open_resp(0, 0, &fh);

    debug_smb_message(resp);
    smb_message_dtor(resp);
    return 0;
}
