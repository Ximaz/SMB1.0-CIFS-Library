#ifndef __SMB_COM_CREATE_DIRECTORY_H_
#define __SMB_COM_CREATE_DIRECTORY_H_

#include "../smb_cifs.h"

typedef struct s_smb_com_create_directory_response
{

} smb_com_create_directory_response_t;

/**
 * @brief This is an original Core Protocol command. This command is
 * deprecated. Clients SHOULD use the TRANS2_CREATE_DIRECTORY subcommand.
 *
 * The Create Directory command creates a new directory on the server, relative
 * to a connected share. The client MUST provide a valid UID and TID, as well
 * as the pathname (relative to the TID) of the directory to be created.
 *
 * Servers MUST require clients to have, at minimum, create permission within
 * the parent directory in order to create a new directory. The creator's
 * access rights to the new directory are be determined by local policy on the
 * server.
 *
 * @param uid A valid UID MUST be provided. At minimum, the user MUST have
 * create permission for the subtree that is to contain the new directory. The
 * creator's access rights to the new directory are determined by local policy
 * on the server.
 * @param tid A valid TID MUST be provided. The TID represents the root of the
 * directory tree in which the new directory is created.
 * @return The allocated message on success, NULL otherwise.
 * @note Deprecated.
 */
smb_message_t smb_com_create_directory(
    UID uid,
    TID tid,
    const char *pathname
);

#endif /* !__SMB_COM_CREATE_DIRECTORY_H_ */
