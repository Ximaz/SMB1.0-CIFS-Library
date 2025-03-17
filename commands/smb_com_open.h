#ifndef __SMB_COM_OPEN_H_
#define __SMB_COM_OPEN_H_

#include "../smb_cifs.h"

/**
 * @brief This is an original Core Protocol command. This command has been
 * deprecated. Client implementations SHOULD use SMB_COM_NT_CREATE_ANDX.
 *
 * This request is used to open an existing regular file. This command MUST NOT
 * be used to open directories or named pipes. The command includes the
 * pathname of the file, relative to the TID, that the client wishes to open.
 * If the command is successful, the server response MUST include a FID. The
 * client MUST supply the FID in subsequent operations on the file.
 *
 * @param uid A valid UID.
 * @param tid A valid TID MUST be provided. The TID represents the root of the
 * directory tree in which the file is created.
 * @param pathname The path to A null-terminated string giving the full
 * pathname, relative to the supplied TID, of the file to be open.
 * @param flags The flags to request an Exclusive Opportunistic lock (Oplock),
 * or a Batch Exclusive Oplock.
 * @param access_mode Bitfields used to describe the permissions to access the
 * file.
 * @param search_attribute Specifies the type of file. This field is used as a
 * search mask. Both the FileName and the SearchAttributes of a file MUST match
 * in order for the file to be opened.
 * @return The allocated message on success, NULL otherwise.
 * @note Deprecated.
 */
smb_message_t smb_com_open_req(
    UID uid,
    TID tid,
    const char *pathname,
    smb_flags_t flags,
    smb_access_mode_t access_mode,
    smb_ext_file_attr_t search_attribute);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_OPEN command.
 *
 * @param resp The raw bytes sent by the server as a response.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_open_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code);

#endif /* !__SMB_COM_OPEN_H_ */
