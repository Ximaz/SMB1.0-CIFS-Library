#ifndef __SMB_COM_RENAME_H_
#define __SMB_COM_RENAME_H_

#include "../smb_cifs.h"

/**
 * @brief This is an original Core Protocol command.
 *
 * This command changes the name of one or more files or directories. It
 * supports the use of wildcards in file names, allowing the renaming of
 * multiple files in a single request
 *
 * @param uid A valid UID.
 * @param tid A valid TID MUST be provided. The TID represents the root of the
 * directory tree in which the file is created.
 * @param old_filename A null-terminated string that contains the name of the
 * file or files to be renamed. Wildcards MAY be used in the filename component
 * of the path.
 * @param new_filename A null-terminated string containing the new name(s) to
 * be given to the file(s) that matches OldFileName or the name of the
 * destination directory into which the files matching OldFileName MUST be
 * moved.
 * @param search_attributes A 16-bit field of 1-bit flags that represent the file
 * @param match_long_filenames Wildcard pattern matching behavior. If this flag
 * is not set, wildcard patterns MUST compare against 8.3 names only. If a file
 * has a long name, the wildcard pattern MUST be compared to that file's 8.3
 * name. If this flag is set, file names can be long file names and wildcard
 * patterns MUST compare against the long file name of a file if it is
 * available. (Either 1 or 0)
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_rename_req(
    UID uid,
    TID tid,
    const char *old_filename,
    const char *new_filename,
    smb_file_attributes_t search_attributes,
    int match_long_filenames
);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_RENAME command.
 *
 * @param error_class The kind of error to return.
 * @param error_code The error code belonging to the error class.
 * @param file_handle All the informations about the created file.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_rename_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code);

#endif /* !__SMB_COM_RENAME_H_ */
