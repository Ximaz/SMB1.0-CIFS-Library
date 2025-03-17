#ifndef __SMB_COM_CREATE_DIRECTORY_H_
#define __SMB_COM_CREATE_DIRECTORY_H_

#include "../smb_cifs.h"

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
smb_message_t smb_com_create_directory_req(
    UID uid,
    TID tid,
    const char *pathname);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_CREATE_DIRECTORY command.
 *
 * @param resp The raw bytes sent by the server as a response.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_create_directory_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code);

#endif /* !__SMB_COM_CREATE_DIRECTORY_H_ */
