#ifndef __SMB_COM_DELETE_DIRECTORY_H_
#define __SMB_COM_DELETE_DIRECTORY_H_

#include "../smb_cifs.h"

/**
 * @brief This is an original Core Protocol command. This command is used to
 * delete an empty directory.
 *
 * @param uid A valid UID MUST be provided. At minimum, the user MUST have
 * delete permission for the subtree that contains the directory. The
 * suppressor's access rights to the directory are determined by local policy
 * on the server.
 * @param tid A valid TID MUST be provided. The TID represents the root of the
 * directory tree in which the directory is deleted.
 * @param pathname A null-terminated string that contains the full pathname,
 * relative to the supplied TID, of the directory to be deleted.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_delete_directory_req(
    UID uid,
    TID tid,
    const char *pathname);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_DELETE_DIRECTORY command.
 *
 * @param resp The raw bytes sent by the server as a response.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_delete_directory_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code);

#endif /* !__SMB_COM_DELETE_DIRECTORY_H_ */
