#ifndef __SMB_COM_DELETE_H_
#define __SMB_COM_DELETE_H_

#include "../smb_cifs.h"

/**
 * @brief This is an original Core Protocol command.
 *
 * This command is used by the client to delete one or more regular files. It
 * supports the use of wildcards in file names, allowing for deletion of
 * multiple files in a single request.
 *
 * @param uid A valid UID.
 * @param tid A valid TID MUST be provided. The TID represents the root of the
 * directory tree in which the file is deleted.
 * @param filename The pathname of the file(s) to be deleted, relative to the
 * supplied TID. Wildcards MAY be used in the filename component of the path.
 * @param search_attributes The file attributes of the file(s) to be deleted.
 * If the value of this field is 0x0000, then only normal files MUST be matched
 * for deletion. If the System or Hidden attributes MUST be specified, then
 * entries with those attributes are matched in addition to the normal files.
 * Read-only files MUST NOT be deleted. The read-only attribute of the file
 * MUST be cleared before the file can be deleted.
 * @param match_long_filenames Wildcard pattern matching behavior. If this flag
 * is not set, wildcard patterns MUST compare against 8.3 names only. If a file
 * has a long name, the wildcard pattern MUST be compared to that file's 8.3
 * name. If this flag is set, file names can be long file names and wildcard
 * patterns MUST compare against the long file name of a file if it is
 * available. (Either 1 or 0)
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_delete_req(
    UID uid,
    TID tid,
    const char *filename,
    smb_file_attributes_t search_attributes,
    int match_long_filenames
);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_DELETE command.
 *
 * @param error_class The kind of error to return.
 * @param error_code The error code belonging to the error class.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_delete_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code);

#endif /* !__SMB_COM_DELETE_H_ */
