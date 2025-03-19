#ifndef __SMB_COM_FLUSH_H_
#define __SMB_COM_FLUSH_H_

#include "../smb_cifs.h"

/**
 * @brief This is an original Core Protocol command.
 *
 * This command requests that the server flush data and allocation information
 * for a specified file or for all open files under the session.
 *
 * @param uid A valid UID.
 * @param fid The FID of the file to be flushed. If this field is set to 0xFFFF
 * (65535), all files opened by the same PID within the SMB connection are to
 * be flushed.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_flush_req(
    UID uid,
    FID fid);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_FLUSH command.
 *
 * @param error_class The kind of error to return.
 * @param error_code The error code belonging to the error class.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_flush_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code);

#endif /* !__SMB_COM_FLUSH_H_ */
