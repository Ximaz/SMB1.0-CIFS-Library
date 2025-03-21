#ifndef __SMB_COM_READ_H_
#define __SMB_COM_READ_H_

#include "../smb_cifs.h"

/**
 * @brief This is an original Core Protocol command. This command is
 * deprecated. Clients SHOULD use SMB_COM_READ_ANDX.
 *
 * This command is used to read bytes from a regular file. If the client has
 * negotiated a protocol that supports named pipes or directly accessible
 * devices, this command can also be used to read from those objects. The end
 * of file condition is indicated by the server returning fewer bytes than the
 * client requested. A read request starting at or beyond the end of the file
 * returns zero bytes. If a read requests more data than can be placed in a
 * message of MaxBufferSize for the SMB connection, the server MUST abort the
 * connection to the client. Because this client request supports 32-bit
 * offsets only, it is inappropriate for files that have 64-bit offsets. The
 * client MUST have at least read access to the file.
 *
 * @param uid A valid UID.
 * @param fid This field MUST be a valid 16-bit signed integer indicating the
 * file from which the data MUST be read.
 * @param count_of_bytes_to_read This field is a 16-bit unsigned integer
 * indicating the number of bytes to be read from the file. The client MUST
 * ensure that the amount of data requested will fit in the negotiated maximum
 * buffer size.
 * @param read_offset_in_bytes This field is a 32-bit unsigned integer
 * indicating the offset, in number of bytes, from which to begin reading from
 * the file. The client MUST ensure that the amount of data requested fits in
 * the negotiated maximum buffer size. Because this field is limited to 32
 * bits, this command is inappropriate for files having 64-bit offsets.
 * @param estimate_of_remaning_bytes_to_be_read This field is a 16-bit unsigned
 * integer indicating the remaining number of bytes that the client intends to
 * read from the file. This is an advisory field and MAY be 0x0000.
 * @param read_if_execute If the bit is set and client has execute permission
 * on the file, then the client MAY read the file even if the client does not
 * have READ permission. This flag is also known as SMB_FLAGS2_PAGING_IO.
 * (Either 1 or 0)
 * @return The allocated message on success, NULL otherwise.
 * @note Deprecated.
 */
smb_message_t smb_com_read_req(
    UID uid,
    FID fid,
    USHORT count_of_bytes_to_read,
    ULONG read_offset_in_bytes,
    USHORT estimate_of_remaning_bytes_to_be_read,
    int read_if_execute);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_READ command.
 *
 * @param error_class The kind of error to return.
 * @param error_code The error code belonging to the error class.
 * @param count_of_bytes_returned The actual number of bytes returned to the
 * client. This MUST be equal to CountOfBytesToRead unless the end of file was
 * reached before reading CoutOfBytesToRead bytes or the ReadOffsetInBytes
 * pointed at or beyond the end of file.
 * @param count_of_bytes_read The number of bytes read that are contained in
 * the following array of bytes.
 * @param bytes The actual bytes read from the file.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_read_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code,
    USHORT count_of_bytes_returned,
    USHORT count_of_bytes_read,
    const UCHAR *bytes);

#endif /* !__SMB_COM_READ_H_ */
