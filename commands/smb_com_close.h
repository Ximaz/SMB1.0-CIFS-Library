#ifndef __SMB_COM_CLOSE_H_
#define __SMB_COM_CLOSE_H_

#include "../smb_cifs.h"

/**
 * @brief This is an original Core Protocol command.
 *
 * This command is used by the client to close an instance of an object
 * associated with a valid FID.
 *
 * @param uid A valid UID.
 * @param fid The FID of the object to be closed.
 * @param last_time_modified A time value encoded as the number of seconds
 * since January 1, 1970 00:00:00.0. The client can request that the last
 * modification time for the file be updated to this time value. A value of
 * 0x00000000 or 0xFFFFFFFF results in the server not updating the last
 * modification time.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_close_req(
    UID uid,
    FID fid,
    UTIME last_time_modified
);

/**
 * @brief This function creates an SMB Message representing the response from
 * the server to the SMB_COM_CLOSE command.
 *
 * @param error_class The kind of error to return.
 * @param error_code The error code belonging to the error class.
 * @return The allocated message on success, NULL otherwise.
 */
smb_message_t smb_com_close_resp(
    smb_error_class_t error_class,
    smb_error_code_t error_code);

#endif /* !__SMB_COM_CLOSE_H_ */
