#ifndef __SMB_COM_QUERY_INFORMATION_H_
#define __SMB_COM_QUERY_INFORMATION_H_

#include "../smb_cifs.h"

#pragma pack(1)

typedef struct __attribute__((packed)) s_smb_com_query_information_result
{
    /**
     * @brief This field is a 16-bit unsigned bit field encoded as
     * SMB_FILE_ATTRIBUTES.
     */
    smb_file_attributes_t file_attributes;

    /**
     * @brief The time of the last write to the file.
     */
    UTIME last_write_time;

    /**
     * @brief This field contains the size of the file, in bytes. Because this
     * size is limited to 32 bits, this command is inappropriate for files
     * whose size is too large.
     */
    ULONG file_size;

    /**
     * @brief This field is reserved, and all entries MUST be set to 0x00.
     */
    USHORT _reserved[5];
} smb_com_query_information_result_t;

#pragma pack()

/**
 * @brief This is an original Core Protocol command. This command is
 * deprecated. New client implementations SHOULD use the SMB_COM_TRANSACTION2
 * subcommand TRANS2_QUERY_PATH_INFORMATION instead.
 *
 * This command MAY be sent by a client to obtain attribute information about a
 * file using the name and path to the file. No FID is required.
 *
 * @param uid A valid UID.
 * @param tid A valid TID MUST be provided. The TID represents the root of the
 * directory tree in which the file is stored.
 * @param filename A null-terminated string that represents the fully qualified
 * name of the file relative to the supplied TID. This is the file for which
 * attributes are queried and returned.
 * @return The allocated message on success, NULL otherwise.
 * @note Deprecated.
 */
smb_message_t smb_com_query_information_req(
    UID uid,
    TID tid,
    const char *filename
);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_QUERY_INFORMATION command.
 *
 * @param error_class The kind of error to return.
 * @param error_code The error code belonging to the error class.
 * @param file_information All the informations about the file.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_query_information_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code,
    const smb_com_query_information_result_t *file_information);

#endif /* !__SMB_COM_QUERY_INFORMATION_H_ */
