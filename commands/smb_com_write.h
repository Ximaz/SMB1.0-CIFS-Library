#ifndef __SMB_COM_WRITE_H_
#define __SMB_COM_WRITE_H_

#include "../smb_cifs.h"

/**
 * @brief This is an original Core Protocol command. This command is
 * deprecated. Clients SHOULD use the SMB_COM_WRITE_ANDX command. Support for
 * named pipes and I/O devices was introduced in the LAN Manager 1.0 dialect.
 *
 * This command is used to write bytes to a regular file. If the client has
 * negotiated a protocol dialect that supports named pipes, mailslots, or
 * directly accessible devices, this command MAY also be used to write to those
 * object. This command MAY also be used to truncate a file to a specified
 * point or to extend a file beyond its current size. The command MUST include
 * a valid TID and FID in the request. This command supports 32-bit offsets
 * only and is inappropriate for files having 64-bit offsets. The client SHOULD
 * use SMB_COM_WRITE_ANDX to write to files requiring a 64-bit file offset.
 * When FID represents a disk file and the request specifies a byte range
 * (WriteOffsetInBytes) beyond the current end of file, the file MUST be
 * extended. Any bytes between the previous end of file and the requested
 * offset are initialized to 0x00. When a write specifies a length
 * (CountOfBytesToWrite) of 0x0000, the file is truncated (or extended) to the
 * length specified by the offset. The client MUST have at least write access
 * to the file.
 * @param uid A valid UID.
 * @param fid This field MUST be a valid 16-bit unsigned integer indicating the
 * file to which the data MUST be written.
 * @param count_of_bytes_to_write This field is a 16-bit unsigned integer
 * indicating the number of bytes to be written to the file. The client MUST
 * ensure that the amount of data sent can fit in the negotiated maximum buffer
 * size.
 * @param write_offset_in_bytes This field is a 32-bit unsigned integer
 * indicating the offset, in number of bytes, from the beginning of the file at
 * which to begin writing to the file. The client MUST ensure that the amount
 * of data sent fits in the negotiated maximum buffer size. Because this field
 * is limited to 32 bits, this command is inappropriate for files that have
 * 64-bit offsets.
 * @param estimate_of_remaning_bytes_to_be_read This field is a 16-bit unsigned
 * integer indicating the remaining number of bytes that the client anticipates
 * to write to the file. This is an advisory field and can be 0x0000. This
 * information can be used by the server to optimize cache behavior.
 * @param bytes The raw bytes to be written to the file.
 * @return The allocated message on success, NULL otherwise.
 * @note Deprecated.
 */
smb_message_t smb_com_write_req(
    UID uid,
    FID fid,
    USHORT count_of_bytes_to_write,
    ULONG write_offset_in_bytes,
    USHORT estimate_of_remaning_bytes_to_be_written,
    const UCHAR *bytes);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_WRITE command.
 *
 * @param error_class The kind of error to return.
 * @param error_code The error code belonging to the error class.
 * @param count_of_bytes_written Indicates the actual number of bytes written
 * to the file. For successful writes, this MUST equal the CountOfBytesToWrite
 * in the client Request. If the number of bytes written differs from the
 * number requested and no error is indicated, then the server has no resources
 * available to satisfy the complete write.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_write_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code,
    USHORT count_of_bytes_written);

#endif /* !__SMB_COM_WRITE_H_ */
