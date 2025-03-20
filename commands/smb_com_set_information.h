#ifndef __SMB_COM_SET_INFORMATION_H_
#define __SMB_COM_SET_INFORMATION_H_

#include "../smb_cifs.h"

/**
 * @brief This is an original Core Protocol command. This command is
 * deprecated. New client implementations SHOULD use the SMB_COM_TRANSACTION2
 * subcommand TRANS2_SET_PATH_INFORMATION instead.
 *
 * This command MAY be sent by a client to change the attribute information of
 * a regular file or directory.
 *
 * Support of all parameters is optional. A server that does not implement one
 * of the parameters MUST ignore that field. If the LastWriteTime field
 * contains 0x00000000, then the file's LastWriteTime MUST NOT be changed.
 *
 * @param uid A valid UID.
 * @param tid A valid TID MUST be provided. The TID represents the root of the
 * directory tree in which the file is created.
 * @param filename A null-terminated string that represents the fully qualified
 * name of the file relative to the supplied TID. This is the file for which
 * attributes are set.
 * @param file_attributes This field is a 16-bit unsigned bit field encoded as
 * SMB_FILE_ATTRIBUTES.
 * @param last_write_time The time of the last write to the file.
 * @return The allocated message on success, NULL otherwise.
 * @note Deprecated.
 */
smb_message_t smb_com_set_information_req(
    UID uid,
    TID tid,
    const char *filename,
    smb_file_attributes_t file_attributes,
    UTIME last_write_time);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_SET_INFORMATION command.
 *
 * @param error_class The kind of error to return.
 * @param error_code The error code belonging to the error class.
 * @param file_handle All the informations about the created file.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_set_information_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code);

#endif /* !__SMB_COM_SET_INFORMATION_H_ */
