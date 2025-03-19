#ifndef __SMB_COM_CREATE_H_
#define __SMB_COM_CREATE_H_

#include "../smb_cifs.h"

#pragma pack(1)

typedef struct __attribute__((packed)) s_smb_com_create_file
{
    /**
     * @brief The FID returned for the created file.
     */
    FID fid;
} smb_com_create_file_t;

#pragma pack()

/**
 * @brief This is an original Core Protocol command. This command is
 * deprecated. Implementations SHOULD use SMB_COM_NT_CREATE_ANDX.
 *
 * This command is used to create and open a new file or open and truncate an
 * existing file to zero length. The FID that is returned can be used in
 * subsequent read, write, lock, unlock, and close messages. This command MUST
 * NOT be used to create directories or named pipes. The request includes the
 * pathname of the file relative to the supplied TID that the client wishes to
 * create. If the command is successful, the server response MUST include a
 * FID. The client MUST supply the FID in subsequent operations on the file.
 * The client MUST have write permission on the file's parent directory in
 * order to create a new file, or write permissions on the file itself in order
 * to truncate the file. The client's access permissions on a newly created
 * file MUST be read/write. Access permissions on truncated files are not
 * modified. The file is opened in read/write/compatibility mode.
 *
 * @param uid A valid UID.
 * @param tid A valid TID MUST be provided. The TID represents the root of the
 * directory tree in which the file is created.
 * @param pathname The path to A null-terminated string giving the full
 * pathname, relative to the supplied TID, of the file to be open.
 * @param file_attributes A 16-bit field of 1-bit flags that represent the file
 * attributes to assign to the file if it is created successfully.
 * @param creation_time The time that the file was created, represented as the
 * number of seconds since Jan 1, 1970, 00:00:00.0.
 * @return The allocated message on success, NULL otherwise.
 * @note Deprecated.
 */
smb_message_t smb_com_create_req(
    UID uid,
    TID tid,
    const char *pathname,
    smb_file_attributes_t file_attributes,
    UTIME creation_time
);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_CREATE command.
 *
 * @param error_class The kind of error to return.
 * @param error_code The error code belonging to the error class.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_create_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code,
    const smb_com_create_file_t *file_handle);

#endif /* !__SMB_COM_CREATE_H_ */
