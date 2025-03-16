#ifndef __SMB_CIFS_H_
#define __SMB_CIFS_H_

typedef unsigned char UCHAR;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef int DWORD;

#define SMB_GEA_ATTR_NAME_MAX_LEN (1 << 8) - 1
#define SMB_FEA_ATTR_NAME_MAX_LEN SMB_GEA_ATTR_NAME_MAX_LEN
#define SMB_FEA_ATTR_VALUE_MAX_LEN (1 << 16) - 1

/**
 * @brief The SMB_GEA data structure is used in Transaction2 subcommand
 * requests to request specific extended attribute (EA) name/value pairs by
 * name. This structure is used when the SMB_INFO_QUERY_EAS_FROM_LIST
 * information level is specified. "GEA" stands for "get extended attribute".
 */
typedef struct s_smb_gea
{
    /**
     * @brief This field MUST contain the length, in bytes (excluding the
     * trailing null padding byte), of the AttributeName field.
     *
     * @note The unit of measurement is the byte (b).
     */
    UCHAR attribute_name_length;

    /**
     * @brief This field contains the name, in extended ASCII (OEM) characters,
     * of an extended attribute. The length of the name MUST NOT exceed 255
     * bytes. An additional byte is added to store a null padding byte. This
     * field MAY be interpreted as an OEM_STRING.
     *
     * @note The unit of measurement is the byte (b).
     *
     * @warning When such structure is being sent over the wire, and even more
     * when it gets concatenated in an SMB GEAList, all attribute names MUST BE
     * trimmed of their remaning right zeroes that were stack allocated but not
     * used.
     */
    UCHAR attribute_name[SMB_GEA_ATTR_NAME_MAX_LEN];
} smb_gea_t;

/**
 * @brief The SMB_GEA_LIST data structure is used to send a concatenated list
 * of SMB_GEA structures.
 */
typedef struct s_smb_gea_list
{
    /**
     * @brief This field MUST contain the total size of the GEAList field, plus
     * the size of the SizeOfListInBytes field (4 bytes).
     *
     * @note The unit of measurement is the byte (b).
     */
    ULONG size_of_list;

    /**
     * @brief A concatenated list of SMB_GEA structures.
     */
    UCHAR *gea_list;
} smb_gea_list_t;

/**
 * @brief The SMB_FEA data structure is used in Transaction2 subcommands and in
 * the NT_TRANSACT_CREATE subcommand to encode an extended attribute (EA)
 * name/value pair. "FEA" stands for "full extended attribute".
 */
typedef struct s_smb_fea
{
    /**
     * @brief This is a bit field. Only the 0x80 bit is defined.
     *
     * 0x7F : Reserved.
     *
     * 0x80 : If set (1), this bit indicates that extended attribute (EA)
     *        support is required on this file. Otherwise, EA support is not
     *        required. If this flag is set, the file to which the EA belongs
     *        cannot be properly interpreted without understanding the
     *        associated extended attributes.
     *        A CIFS client that supports EAs can set this bit when adding an
     *        EA to a file residing on a server that also supports EAs. The
     *        server MUST NOT allow this bit to be set on an EA associated with
     *        directories.
     *        If this bit is set on any EA associated with a file on the
     *        server, the server MUST reject client requests to open the file
     *        (except to truncate the file) if the SMB_FLAGS2_EAS flag is not
     *        set in the request header. In this case, the server SHOULD fail
     *        this request with STATUS_ACCESS_DENIED (ERRDOS/ERRnoaccess) in
     *        the Status field of the SMB Header in the server response.
     */
    UCHAR extended_attribute_flag;

    /**
     * @brief This field MUST contain the length, in bytes, of the
     * AttributeName field (excluding the trailing null byte).
     *
     * @note The unit of measurement is the byte (b).
     */
    UCHAR attribute_name_length;

    /**
     * @brief This field MUST contain the length, in bytes, of the
     * AttributeValue field.
     *
     * @note The unit of measurement is the byte (b).
     */
    USHORT attribute_value_length;

    /**
     * @brief This field contains the name, in extended ASCII (OEM) characters,
     * of an extended attribute. The length of the name MUST NOT exceed 255
     * bytes. An additional byte is added to store a null padding byte. This
     * field MAY be interpreted as an OEM_STRING.
     *
     * @warning When such structure is being sent over the wire, and even more
     * when it gets concatenated in an SMB FEAList, all attribute names MUST BE
     * trimmed of their remaning right zeroes that were stack allocated but not
     * used.
     */
    UCHAR attribute_name[SMB_FEA_ATTR_NAME_MAX_LEN];

    /**
     * @brief This field contains the value of an extended file attribute. The
     * value is expressed as an array of extended ASCII (OEM) characters. This
     * array MUST NOT be null-terminated, and its length MUST NOT exceed 65,535
     * bytes.
     *
     * @warning When such structure is being sent over the wire, and even more
     * when it gets concatenated in an SMB FEAList, all attribute names MUST BE
     * trimmed of their remaning right zeroes that were stack allocated but not
     * used.
     */
    UCHAR attribute_value[SMB_FEA_ATTR_VALUE_MAX_LEN];
} smb_fea_t;

/**
 * @brief The SMB_FEA_LIST data structure is used to send a concatenated list
 * of SMB_FEA structures.
 */
typedef struct s_smb_fea_list
{
    /**
     * @brief This field MUST contain the total size of the FEAList field, plus
     * the size of the SizeOfListInBytes field (4 bytes).
     */
    ULONG size_of_list;

    /**
     * @brief A concatenated list of SMB_FEA structures.
     */
    UCHAR *fea_list;
} smb_fea_list_t;

/**
 * @brief A 32-bit field containing encoded file attribute values and file
 * access behavior flag values. The attribute and flag value names are for
 * reference purposes only. If ATTR_NORMAL (see following) is set as the
 * requested attribute value, it MUST be the only attribute value set.
 * Including any other attribute value causes the ATTR_NORMAL value to be
 * ignored. Any combination of the flag values (see following) is acceptable.
 */
typedef enum e_smb_ext_file_attr
{
    /**
     * @brief The file is read only. Applications can read the file but cannot
     * write to it or delete it.
     */
    ATTR_READONLY = 0x00000001,

    /**
     * @brief The file is hidden. It is not to be included in an ordinary
     * directory listing.
     */
    ATTR_HIDDEN = 0x00000002,

    /**
     * @brief The file is part of or is used exclusively by the operating
     * system.
     */
    ATTR_SYSTEM = 0x00000004,

    /**
     * @brief The file is a directory.
     */
    ATTR_DIRECTORY = 0x00000010,

    /**
     * @brief The file has not been archived since it was last modified.
     */
    ATTR_ARCHIVE = 0x00000020,

    /**
     * @brief The file has no other attributes set. This attribute is valid
     * only if used alone.
     */
    ATTR_NORMAL = 0x00000080,

    /**
     * @brief The file is temporary. This is a hint to the cache manager that
     * it does not need to flush the file to backing storage.
     */
    ATTR_TEMPORARY = 0x00000100,

    /**
     * @brief The file or directory is compressed. For a file, this means that
     * all of the data in the file is compressed. For a directory, this means
     * that compression is the default for newly created files and
     * subdirectories.
     */
    ATTR_COMPRESSED = 0x00000800,

    /**
     * @brief Indicates that the file is to be accessed according to POSIX
     * rules. This includes allowing multiple files with names differing only
     * in case, for file systems that support such naming.
     */
    POSIX_SEMANTICS = 0x01000000,

    /**
     * @brief Indicates that the file is being opened or created for a backup
     * or restore operation. The server SHOULD allow the client to override
     * normal file security checks, provided it has the necessary permission to
     * do so.
     */
    BACKUP_SEMANTICS = 0x02000000,

    /**
     * @brief Requests that the server delete the file immediately after all of
     * its handles have been closed.
     */
    DELETE_ON_CLOSE = 0x04000000,

    /**
     * @brief Indicates that the file is to be accessed sequentially from
     * beginning to end.
     */
    SEQUENTIAL_SCAN = 0x08000000,

    /**
     * @brief Indicates that the application is designed to access the file
     * randomly. The server can use this flag to optimize file caching.
     */
    RANDOM_ACCESS = 0x10000000,

    /**
     * @brief Requests that the server open the file with no intermediate
     * buffering or caching; the server might not honor the request. The
     * application MUST meet certain requirements when working with files
     * opened with FILE_FLAG_NO_BUFFERING. File access MUST begin at offsets
     * within the file that are integer multiples of the volume's sector size
     * and MUST be for numbers of bytes that are integer multiples of the
     * volume's sector size. For example, if the sector size is 512 bytes, an
     * application can request reads and writes of 512, 1024, or 2048 bytes,
     * but not of 335, 981, or 7171 bytes.
     */
    NO_BUFFERING = 0x20000000,

    /**
     * @brief Instructs the operating system to write through any intermediate
     * cache and go directly to the file. The operating system can still cache
     * write operations, but cannot lazily flush them.
     */
    WRITE_THROUGH = 0x80000000
} smb_ext_file_attr_t;

typedef DWORD SMB_EXT_FILE_ATTR;

/**
 * @brief An unsigned 16-bit field that defines the basic file attributes
 * supported by the SMB Protocol. In addition, exclusive search attributes
 * (those Names prefixed with SMB_SEARCH_ATTRIBUTE) are defined for use when
 * searching for files within a directory.
 */
typedef enum e_smb_file_attributes
{
    /**
     * @brief Normal file.
     */
    SMB_FILE_ATTRIBUTE_NORMAL = 0x0000,

    /**
     * @brief Read-only file.
     */
    SMB_FILE_ATTRIBUTE_READONLY = 0x0001,

    /**
     * @brief Hidden file.
     */
    SMB_FILE_ATTRIBUTE_HIDDEN = 0x0002,

    /**
     * @brief System file.
     */
    SMB_FILE_ATTRIBUTE_SYSTEM = 0x0004,

    /**
     * @brief Volume Label.
     */
    SMB_FILE_ATTRIBUTE_VOLUME = 0x0008,

    /**
     * @brief Directory file.
     */
    SMB_FILE_ATTRIBUTE_DIRECTORY = 0x0010,

    /**
     * @brief File changed since last archive.
     */
    SMB_FILE_ATTRIBUTE_ARCHIVE = 0x0020,

    /**
     * @brief Search for Read-only files.
     */
    SMB_SEARCH_ATTRIBUTE_READONLY = 0x0100,

    /**
     * @brief Search for Hidden files.
     */
    SMB_SEARCH_ATTRIBUTE_HIDDEN = 0x0200,

    /**
     * @brief Search for System files.
     */
    SMB_SEARCH_ATTRIBUTE_SYSTEM = 0x0400,

    /**
     * @brief Search for Directory files.
     */
    SMB_SEARCH_ATTRIBUTE_DIRECTORY = 0x1000,

    /**
     * @brief Search for files that have changed since they were last archived.
     */
    SMB_SEARCH_ATTRIBUTE_ARCHIVE = 0x2000,

    /**
     * @brief Reserved.
     */
    SMB_FILE_ATTRIBUTE_OTHER = 0xC8C0
} smb_file_attributes_t;

/**
 * @brief The SMB_NMPIPE_STATUS data type is a 16-bit field that encodes the
 * status of a named pipe. Any combination of the following flags MUST be
 * valid. The ReadMode and NamedPipeType bit fields are defined as 2-bit
 * integers. Subfields marked Reserved SHOULD be set to zero by the server and
 * MUST be ignored by the client.
 */
typedef enum e_smb_nmpipe_status
{
    /**
     * @brief An 8-bit unsigned integer that gives the maximum number of
     * instances the named pipe can have.
     */
    I_COUNT = 0x000FF,

    /**
     * @brief
     * 0 : This bit field indicates the client read mode for the named pipe.
     * This bit field has no effect on writes to the named pipe. A value of
     * zero indicates that the named pipe was opened in or set to byte mode by
     * the client.
     *
     * 1 : A value of 1 indicates that the client opened or set the named pipe
     * to message mode.
     *
     * 2, 3 : Reserved. Bit 0x0200 MUST be ignored.
     */
    READ_MODE = 0x0300,

    /**
     * @brief
     *
     * 0 : This bit field indicates the type of the named pipe when the named
     * pipe was created by the server. A value of zero indicates that the named
     * pipe was created as a byte mode pipe.
     *
     * 1 : The named pipe was created by the server as a message mode pipe.
     *
     * 2,3 : Reserved. Bit 0x0800 MUST be ignored.
     */
    NAMED_PIPE_TYPE = 0x0C00,

    /**
     * @brief
     *
     * 0 : Client-side end of the named pipe. The SMB server MUST clear the
     * Endpoint bit (set it to zero) when responding to the client request
     * because the CIFS client is a consumer requesting service from the named
     * pipe. When this bit is clear, it indicates that the client is accessing
     * the consumer endpoint.
     *
     * 1 : Indicates the server end of the pipe.
     */
    ENDPOINT = 0x4000,

    /**
     * @brief
     *
     * 0 : A named pipe read or raw read request will wait (block) until
     * sufficient data to satisfy the read request becomes available, or until
     * the request is canceled.
     * A named pipe write or raw write request blocks until its data is
     * consumed, if the write request length is greater than zero.
     *
     * 1 : A read or a raw read request returns all data available to be read
     * from the named pipe, up to the maximum read size set in the request.
     * Write operations return after writing data to named pipes without
     * waiting for the data to be consumed.
     * Named pipe non-blocking raw writes are not allowed. Raw writes MUST be
     * performed in blocking mode.
     */
    NONBLOCKING = 0x8000
} smb_nmpipe_status_t;

typedef USHORT SMB_NMPIPE_STATUS;

/**
 * @brief This is a 16-bit value in little-endian byte order used to encode a
 * date. An SMB_DATE value SHOULD be interpreted as follows. The date is
 * represented in the local time zone of the server. The following field names
 * are provided for reference only.
 */
typedef enum e_smb_date
{
    /**
     * @brief The year. Add 1980 to the resulting value to return the actual
     * year.
     */
    YEAR = 0xFE00,

    /**
     * @brief The month. Values range from 1 to 12.
     */
    MONTH = 0x01E0,

    /**
     * @brief The date. Values range from 1 to 31.
     */
    DAY = 0x001F
} smb_date_t;

/**
 * @brief This is a 16-bit value in little-endian byte order used to encode a
 * time of day. The SMB_TIME value is usually accompanied by an SMB_DATE value
 * that indicates what date corresponds with the specified time. An SMB_TIME
 * value SHOULD be interpreted as follows. The field names below are provided
 * for reference only. The time is represented in the local time zone of the server.
 */
typedef enum e_smb_time
{
    /**
     * @brief The hours. Values range from 0 to 23.
     */
    HOUR = 0xF800,

    /**
     * @brief The minutes. Values range from 0 to 59.
     */
    MINUTES = 0x07E0,

    /**
     * @brief The seconds. Values MUST represent two-second increments.
     */
    SECONDS = 0x001F
} smb_time_t;

/**
 * @brief This is a 32-bit unsigned integer in little-endian byte order
 * indicating the number of seconds since Jan 1, 1970, 00:00:00.0.
 */
typedef unsigned int UTIME;

/**
 * @brief An SMB_ERROR MUST be interpreted in one of two ways, depending on the
 * capabilities negotiated between client and server: either as an NTSTATUS
 * value (a 32-bit value in little-endian byte order used to encode an error
 * message, as defined in [MS-ERREF] section 2.3), or as an SMBSTATUS value (as
 * defined following).
 */
typedef struct e_smb_error
{
    /**
     * @brief An SMB error class code.
     */
    UCHAR error_class;

    /**
     * @brief This field is reserved and MUST be ignored by both server and
     * client.
     */
    UCHAR _reserved;

    /**
     * @brief An SMB error code.
     */
    USHORT error_code;
} smb_error_t;

/**
 * @brief File ID.
 * A file handle, representing an open file on the server. A FID returned from
 * an Open or Create operation MUST be unique within an SMB connection.
 *
 * File IDs (FIDs) are generated on CIFS servers. The generation of FIDs MUST
 * satisfy the following constraints:
 * - The FID MUST be a 16-bit opaque value.
 * - The FID MUST be unique within a specified client/server SMB connection.
 * - The FID MUST remain valid for the lifetime of the SMB connection on which
 *   the open request is performed, or until the client sends a request to the
 *   server to close the FID.
 * - Once a FID has been closed, the value can be reused for another create or
 *   open request.
 * - The value 0xFFFF MUST NOT be used as a valid FID. All other possible
 *   values for FID, including zero (0x0000) are valid. The value 0xFFFF is
 *   used to specify all FIDs or no FID, depending upon the context in which it
 *   is used.
 */
typedef short FID;

/**
 * @brief Multiplex ID.
 * The MID is assigned by the client. All messages include a MID along with a
 * PID (process ID, see below) to uniquely identify groups of commands
 * belonging to the same logical thread of operation on the client node. The
 * client MAY use the PID/MID pair to demultiplex command responses and to
 * identify outstanding requests that are pending on the server (see
 * SMB_COM_NT_CANCEL). In earlier SMB Protocol dialects, the MID was defined as
 * a number that uniquely identified a protocol request and response within a
 * process (see [SMB-LM1X]). In CIFS, except where noted, a client MAY have
 * multiple outstanding requests (within the limit set by the MaxMPXCount
 * connection value) with the same PID and MID values. Clients inform servers
 * of the creation of a new thread simply by introducing a new MID into the
 * dialog.
 *
 * Multiplex IDs (MIDs) are generated on CIFS clients. The generation of MIDs
 * MUST satisfy the following constraints:
 * - The MID MUST be a 16-bit opaque value.
 * - The MID MUST be unique with respect to a valid client PID over a single
 *   SMB connection.
 * - The PID/MID pair MUST remain valid as long as there are outstanding
 *   requests on the server identified by that PID/MID pair.
 * - The value 0xFFFF MUST NOT be used as a valid MID. All other possible
 *   values for MID, including zero (0x0000), are valid. The value 0xFFFF is
 *   used in an OpLock Break Notification request, which is an
 *   SMB_COM_LOCKING_ANDX Request sent from the server.
 */
typedef short MID;

/**
 * @brief Process ID.
 * The PID is assigned by the client. The client SHOULD set this to a value
 * that identifies the process on the client node that initiated the request.
 * The server MUST return both the PID and the MID to the client in any
 * response to a client request. Clients inform servers of the creation of a
 * new process simply by introducing a new PID into the dialog. In CIFS, the
 * PID is a 32-bit value constructed by combining two 16-bit fields (PIDLow and
 * PIDHigh) in the SMB Header.
 *
 * Process IDs (PIDs) are generated on the CIFS client. The generation of PIDs
 * MUST satisfy the following constraints:
 * - The PID MUST be a 32-bit opaque value. The PID value is transferred in two
 *   fields (PIDHigh and PIDLow) in the SMB Header.
 * - The PID MUST be unique within a specified client/server SMB connection.
 * - The PID MUST remain valid as long as there are outstanding client requests
 *   at the server.
 * - The value 0xFFFF MUST NOT be used as a valid PIDLow. All other possible
 *   values for PID, including zero (0x0000), are valid. The PIDLow value
 *   0xFFFF is used in an OpLock Break Notification request, which is an
 *   SMB_COM_LOCKING_ANDX Request sent from the server.
 *
 * In earlier dialects of the SMB Protocol, the PID value was a 16-bit unsigned
 * value. The NT LAN Manager dialect introduced the use of the PIDHigh header
 * field to extend the PID value to 32 bits.
 */
typedef int PID;

/**
 * @brief Connection ID.
 * If a connectionless transport is in use, the Connection ID (CID) is
 * generated by the server and passed in the SMB Header of every subsequent SMB
 * message to identify the SMB connection to which the message belongs.
 *
 * In order to support CIFS over connectionless transport, such as Direct IPX,
 * CIFS servers MUST support the generation of Connection IDs (CIDs). The
 * generation of CIDs MUST satisfy the following constraints:
 * - The CID MUST be a 16-bit opaque value.
 * - The CID MUST be unique across all SMB connections carried over
 *   connectionless transports.
 * - The CID MUST remain valid for the lifetime of the SMB connection.
 * - Once the connection has been closed, the CID value can be reused for
 *   another SMB connection.
 * - The values 0x0000 and 0xFFFF MUST NOT be used as valid CIDs. All other
 *   possible values for CID are valid.
 */
typedef int CID;

/**
 * @brief Search ID.
 * A search ID (also known as a SID) is similar to a FID. It identifies an open
 * directory search, the state of which is maintained on the server. Open SIDs
 * MUST be unique to the SMB connection.
 *
 * Search IDs (SIDs) are generated on CIFS servers. The generation of SIDs MUST
 * satisfy the following constraints:
 * - The SID MUST be a 16-bit opaque value for a specific TRANS2_FIND_FIRST2
 *   Request.
 * - The SID MUST be unique for a specified client/server SMB connection.
 * - The SID MUST remain valid for the lifetime of the SMB connection while the
 *   search operation is being performed, or until the client sends a request
 *   to the server to close the SID.
 * - Once a SID has been closed, the value can be reused by another
 *   TRANS2_FIND_FIRST2 Request.
 * - The value 0xFFFF MUST NOT be used as a valid SID. All other possible
 *   values for SID, including zero (0x0000), are valid. The value 0xFFFF is
 *   reserved.
 *
 * The acronym SID is also used to indicate a session ID. The two usages appear
 * in completely different contexts.
 */
typedef int SID;

/**
 * @brief SessionKey.
 * A Session Key is returned in the SMB_COM_NEGOTIATE response received during
 * establishment of the SMB connection. This Session Key is used to logically
 * bind separate virtual circuits (VCs) together. This Session Key is not used
 * in any authentication or message signing. It is returned to the server in
 * the SMB_COM_SESSION_SETUP_ANDX request messages that are used to create SMB
 * sessions.
 *
 * The term "Session Key" also refers to a cryptographic secret key used to
 * perform challenge/response authentication and is also used in the message
 * signing algorithm. For each SMB session, the Session Key is the LM or NTLM
 * password hash used in the generation of the response from the
 * server-supplied challenge. The Session Key used in the first successful user
 * authentication (non-anonymous, non-guest) becomes the signing Session Key
 * for the SMB connection.
 *
 * The term session key, in this context, does not refer to the cryptographic
 * session keys used in authentication and message signing. Rather, it refers
 * to the SessionKey unique identifier sent by the server in the
 * SMB_COM_NEGOTIATE Response.
 *
 * Virtual circuit session keys (SessionKeys) are generated on CIFS servers.
 * The generation of SessionKeys SHOULD satisfy the following constraints:
 * - The SessionKey MUST be a 32-bit opaque value generated by the CIFS server
 *   for a particular SMB connection, and returned in the SMB_COM_NEGOTIATE
 *   Response for that connection.
 * - The SessionKey MUST be unique for a specified client/server SMB
 *   connection.
 * - The SessionKey MUST remain valid for the lifetime of the SMB connection.
 * - Once the SMB connection has been closed, the SessionKey value can be
 *   reused.
 * - There are no restrictions on the permitted values of SessionKey. A value
 *   of 0x00000000 suggests, but does not require, that the server ignore the
 *   SessionKey.
 */
typedef int SESSION_KEY;

/**
 * @brief Tree ID.
 * A TID represents an open connection to a share, otherwise known as a tree
 * connect. An open TID MUST be unique within an SMB connection.
 *
 * Tree IDs (TIDs) are generated on CIFS servers. The generation of TIDs MUST
 * satisfy the following constraints:
 * - The TID MUST be a 16-bit opaque value.
 * - The TID MUST be unique within a specified client/server SMB connection.
 * - The TID MUST remain valid for the lifetime of the SMB connection on which
 *   the tree connect request is performed, or until the client sends a request
 *   to the server to close the TID.
 * - Once a TID has been closed, the value can be reused in the response to
 *   another tree connect request.
 * - The value 0xFFFF MUST NOT be used as a valid TID. All other possible
 *   values for TID, including zero (0x0000), are valid. The value 0xFFFF is
 *   used to specify all TIDs or no TID, depending upon the context in which it
 *   is used.
 */
typedef short TID;

/**
 * @brief User ID.
 * A UID represents an authenticated SMB session (including those created using
 * anonymous or guest authentication). Some implementations refer to this value
 * as a Virtual User ID (VUID) to distinguish it from the user IDs used by the
 * underlying account management system.
 *
 * User IDs (UIDs) are generated on CIFS servers. The generation of UIDs MUST
 * satisfy the following constraints:
 * - The UID MUST be a 16-bit opaque value.
 * - The UID MUST be unique for a specified client/server SMB connection.
 * - The UID MUST remain valid for the lifetime of the SMB connection on which
 *   the authentication is performed, or until the client sends a request to
 *   the server to close the UID (to log off the user).
 * - Once a UID has been closed, the value can be reused in the response to
 *   another authentication request.
 * - The value 0xFFFE was declared reserved in the LAN Manager 1.0
 *   documentation, so a value of 0xFFFE SHOULD NOT be used as a valid UID. All
 *   other possible values for a UID, excluding zero (0x0000), are valid.
 */
typedef short UID;
typedef UID VUID;

/**
 * @brief Following is a listing of all SMB commands used in CIFS and their
 * associated command codes.
 */
typedef enum e_smb_com
{
    /**
     * @brief Create a new directory.
     *
     * @note Deprecated.
     */
    SMB_COM_CREATE_DIRECTOR = 0x00,

    /**
     * @brief Delete an empty directory.
     */
    SMB_COM_DELETE_DIRECTORY = 0x01,

    /**
     * @brief Open a file.
     *
     * @note Deprecated.
     */
    SMB_COM_OPEN = 0x02,

    /**
     * @brief Create or open a file.
     *
     * @note Deprecated.
     */
    SMB_COM_CREATE = 0x03,

    /**
     * @brief Close a file.
     */
    SMB_COM_CLOSE = 0x04,

    /**
     * @brief Flush data for a file, or all files associated with a client, PID
     * pair.
     */
    SMB_COM_FLUSH = 0x05,

    /**
     * @brief Delete a file.
     */
    SMB_COM_DELETE = 0x06,

    /**
     * @brief Rename a file or set of files.
     */
    SMB_COM_RENAME = 0x07,

    /**
     * @brief Get file attributes.
     *
     * @note Deprecated.
     */
    SMB_COM_QUERY_INFORMATION = 0x08,

    /**
     * @brief Set file attributes.
     *
     * @note Deprecated.
     */
    SMB_COM_SET_INFORMATION = 0x09,

    /**
     * @brief Read from a file.
     *
     * @note Deprecated.
     */
    SMB_COM_READ = 0x0A,

    /**
     * @brief Write from a file.
     *
     * @note Deprecated.
     */
    SMB_COM_WRITE = 0x0B,

    /**
     * @brief Request a byte-range lock on a file.
     *
     * @note Deprecated.
     */
    SMB_COM_LOCK_BYTE_RANGE = 0x0C,

    /**
     * @brief Release a byte-range lock on a file.
     *
     * @note Deprecated.
     */
    SMB_COM_UNLOCK_BYTE_RANGE = 0x0D,

    /**
     * @brief Create a temporary file.
     *
     * @note Obselescent.
     */
    SMB_COM_CREATE_TEMPORARY = 0x0E,

    /**
     * @brief Create and open a new file.
     *
     * @note Deprecated.
     */
    SMB_COM_CREATE_NEW = 0x0F,

    /**
     * @brief Verify that the specified pathname resolves to a directory.
     */
    SMB_COM_CHECK_DIRECTORY = 0x10,

    /**
     * @brief Indicate process exit.
     *
     * @note Obselescent.
     */
    SMB_COM_PROCESS_EXIT = 0x11,

    /**
     * @brief Set the current file pointer within a file.
     *
     * @note Obselescent.
     */
    SMB_COM_SEEK = 0x12,

    /**
     * @brief Lock and read a byte-range within a file.
     *
     * @note Deprecated.
     */
    SMB_COM_LOCK_AND_READ = 0x13,

    /**
     * @brief Write and unlock a byte-range within a file.
     *
     * @note Deprecated.
     */
    SMB_COM_WRITE_AND_UNLOCK = 0x14,

    /**
     * @brief Read a block in raw mode.
     *
     * @note Deprecated.
     */
    SMB_COM_READ_RAW = 0x1A,

    /**
     * @brief Multiplexed block read.
     *
     * @note Obselescent.
     */
    SMB_COM_READ_MPX = 0x1B,

    /**
     * @brief Multiplexed block read, secondary request.
     *
     * @note Obselete.
     */
    SMB_COM_READ_MPX_SECONDARY = 0x1C,

    /**
     * @brief Write a block in raw mode.
     *
     * @note Deprecated.
     */
    SMB_COM_WRITE_RAW = 0x1D,

    /**
     * @brief Multiplexed block write.
     *
     * @note Obselescent.
     */
    SMB_COM_WRITE_MPX = 0x1E,

    /**
     * @brief Multiplexed block write, secondary request.
     *
     * @note Obselete.
     */
    SMB_COM_WRITE_MPX_SECONDARY = 0x1F,

    /**
     * @brief Raw block write, final response.
     *
     * @note Deprecated.
     */
    SMB_COM_WRITE_COMPLETE = 0x20,

    /**
     * @brief Reserved, but not implemented.
     *
     * @note Not implemented.
     */
    SMB_COM_QUERY_SERVER = 0x21,

    /**
     * @brief Set an extended set of file attributes.
     *
     * @note Deprecated.
     */
    SMB_COM_SET_INFORMATION2 = 0x22,

    /**
     * @brief Get an extended set of file attributes.
     *
     * @note Deprecated.
     */
    SMB_COM_QUERY_INFORMATION2 = 0x23,

    /**
     * @brief Lock multiple byte ranges; AndX chaining.
     */
    SMB_COM_LOCKING_ANDX = 0x24,

    /**
     * @brief Transaction.
     */
    SMB_COM_TRANSACTION = 0x25,

    /**
     * @brief Transaction secondary request.
     */
    SMB_COM_TRANSACTION_SECONDARY = 0x26,

    /**
     * @brief Pass an I/O Control function request to the server.
     *
     * @note Obselescent.
     */
    SMB_COM_IOCTL = 0x27,

    /**
     * @brief IOCTL secondary request.
     *
     * @note Not implemented.
     */
    SMB_COM_IOCTL_SECONDARY = 0x28,

    /**
     * @brief Copy a file or directory.
     *
     * @note Obselete.
     */
    SMB_COM_COPY = 0x29,

    /**
     * @brief Move a file or directory.
     *
     * @note Obselete.
     */
    SMB_COM_MOVE = 0x2A,

    /**
     * @brief Echo request (ping).
     */
    SMB_COM_ECHO = 0x2B,

    /**
     * @brief Write to and close a file.
     *
     * @note Deprecated.
     */
    SMB_COM_WRITE_AND_CLOSE = 0x2C,

    /**
     * @brief Extended file open with AndX chaining.
     *
     * @note Deprecated.
     */
    SMB_COM_OPEN_ANDX = 0x2D,

    /**
     * @brief Extended file read with AndX chaining.
     */
    SMB_COM_READ_ANDX = 0x2E,

    /**
     * @brief Extended file write with AndX chaining.
     */
    SMB_COM_WRITE_ANDX = 0x2F,

    /**
     * @brief Reserved, but not implemented.
     *
     * @note Not implemented.
     */
    SMB_COM_NEW_FILE_SIZE = 0x30,

    /**
     * @brief Close an open file and tree disconnect.
     *
     * @note Not implemented.
     */
    SMB_COM_CLOSE_AND_TREE_DISC = 0x31,

    /**
     * @brief Transaction 2 format request/response.
     */
    SMB_COM_TRANSACTION2 = 0x32,

    /**
     * @brief Transaction 2 secondary request.
     */
    SMB_COM_TRANSACTION2_SECONDARY = 0x33,

    /**
     * @brief Close an active search.
     */
    SMB_COM_FIND_CLOSE2 = 0x34,

    /**
     * @brief Notification of the closure of an active search.
     *
     * @note Not implemented.
     */
    SMB_COM_FIND_NOTIFY_CLOSE = 0x35,

    /**
     * @brief Tree connect.
     *
     * @note Deprecated.
     */
    SMB_COM_TREE_CONNECT = 0x70,

    /**
     * @brief Tree disconnect.
     */
    SMB_COM_TREE_DISCONNECT = 0x71,

    /**
     * @brief Negotiate protocol dialect.
     */
    SMB_COM_NEGOTIATE = 0x72,

    /**
     * @brief Session Setup with AndX chaining.
     */
    SMB_COM_SESSION_SETUP_ANDX = 0x73,

    /**
     * @brief User logoff with AndX chaining.
     */
    SMB_COM_LOGOFF_ANDX = 0x74,

    /**
     * @brief Tree connect with AndX chaining.
     */
    MB_COM_TREE_CONNECT_ANDX = 0x75,

    /**
     * @brief Negotiate security packages with AndX chaining.
     *
     * @note Not implemented.
     */
    MB_COM_SECURITY_PACKAGE_ANDX = 0x7E,

    /**
     * @brief Retrieve file system information from the server.
     *
     * @note Deprecated.
     */
    SMB_COM_QUERY_INFORMATION_DISK = 0x80,

    /**
     * @brief Directory wildcard search.
     *
     * @note Deprecated.
     */
    SMB_COM_SEARCH = 0x81,

    /**
     * @brief Start or continue an extended wildcard directory search.
     *
     * @note Deprecated.
     */
    SMB_COM_FIND = 0x82,

    /**
     * @brief Perform a one-time extended wildcard directory search.
     *
     * @note Deprecated.
     */
    SMB_COM_FIND_UNIQUE = 0x83,

    /**
     * @brief End an extended wildcard directory search.
     *
     * @note Deprecated.
     */
    SMB_COM_FIND_CLOSE = 0x84,

    /**
     * @brief NT format transaction request/response.
     */
    SMB_COM_NT_TRANSACT = 0xA0,

    /**
     * @brief NT format transaction secondary request.
     */
    SMB_COM_NT_TRANSACT_SECONDARY = 0xA1,

    /**
     * @brief Create or open a file or a directory.
     */
    SMB_COM_NT_CREATE_ANDX = 0xA2,

    /**
     * @brief Cancel a request currently pending at the server.
     */
    SMB_COM_NT_CANCEL = 0xA4,

    /**
     * @brief File rename with extended semantics.
     *
     * @note Obselescent.
     */
    SMB_COM_NT_RENAME = 0xA5,

    /**
     * @brief Create a print queue spool file.
     */
    SMB_COM_OPEN_PRINT_FILE = 0xC0,

    /**
     * @brief Write to a print queue spool file.
     *
     * @note Deprecated.
     */
    SMB_COM_WRITE_PRINT_FILE = 0xC1,

    /**
     * @brief Close a print queue spool file.
     *
     * @note Deprecated.
     */
    SMB_COM_CLOSE_PRINT_FILE = 0xC2,

    /**
     * @brief Request print queue information.
     *
     * @note Not implemented.
     */
    SMB_COM_GET_PRINT_QUEUE = 0xC3,

    /**
     * @brief Reserved, but not implemented.
     *
     * @note Not implemented.
     */
    SMB_COM_READ_BULK = 0xD8,

    /**
     * @brief Reserved, but not implemented.
     *
     * @note Not implemented.
     */
    SMB_COM_WRITE_BULK = 0xD9,

    /**
     * @brief Reserved, but not implemented.
     *
     * @note Not implemented.
     */
    SMB_COM_WRITE_BULK_DATA = 0xDA,

    /**
     * @brief As the name suggests, this command code is a designated invalid
     * command and SHOULD NOT be used.
     */
    SMB_COM_INVALID = 0xFE,

    /**
     * @brief Also known as the "NIL" command. It identifies the end of an AndX
     * Chain, and is only valid in that context.
     */
    SMB_COM_NO_ANDX_COMMAND = 0xFF,
} smb_com_t;

/**
 * @brief Transaction Codes used with SMB_COM_TRANSACTION.
 */
typedef enum e_smb_trans {
    /**
     * @brief Allows a client to write data to a specific mailslot on the
     * server.
     */
    TRANS_MAILSLOT_WRITE = 0x0001,

    /**
     * @brief Used to set the read mode and non-blocking mode of a specified
     * named pipe.
     */
    TRANS_SET_NMPIPE_STATE = 0x0001,

    /**
     * @brief Allows for a raw read of data from a named pipe. This method of
     * reading data from a named pipe ignores message boundaries even if the
     * pipe was set up as a message mode pipe.
     *
     * @note Deprecated.
     */
    TRANS_RAW_READ_NMPIPE = 0x0011,

    /**
     * @brief Allows for a client to retrieve information about a specified
     * named pipe.
     */
    TRANS_QUERY_NMPIPE_STATE = 0x0021,

    /**
     * @brief Used to retrieve pipe information about a named pipe.
     */
    TRANS_QUERY_NMPIPE_INFO = 0x0022,

    /**
     * @brief Used to copy data out of a named pipe without removing it from
     * the named pipe.
     */
    TRANS_PEEK_NMPIPE = 0x0023,

    /**
     * @brief Used to execute a transacted exchange against a named pipe. This
     * transaction has a constraint that it can be used only on a duplex,
     * message-type pipe.
     */
    TRANS_TRANSACT_NMPIPE = 0x0026,

    /**
     * @brief Allows for a raw write of data to a named pipe. Raw writes to
     * named pipes put bytes directly into a pipe, regardless of whether it is
     * a message mode pipe or byte mode pipe.
     *
     * @note Deprecated.
     */
    TRANS_RAW_WRITE_NMPIPE = 0x0031,

    /**
     * @brief Allows a client to read data from a named pipe.
     */
    TRANS_READ_NMPIPE = 0x0036,

    /**
     * @brief Allows a client to write data to a named pipe.
     */
    TRANS_WRITE_NMPIPE = 0x0037,

    /**
     * @brief Allows a client to be notified when the specified named pipe is
     * available to be connected to.
     */
    TRANS_WAIT_NMPIPE = 0x0053,

    /**
     * @brief Connect to a named pipe, issue a write to the named pipe, issue a
     * read from the named pipe, and close the named pipe.
     */
    TRANS_CALL_NMPIPE = 0x0054
} smb_trans_t;

/**
 * @brief Transaction Codes used with SMB_COM_TRANSACTION2.
 */
typedef enum e_smb_trans2 {
    /**
     * @brief Open or create a file and set extended attributes on the file.
     */
    TRANS2_OPEN2 = 0x0000,

    /**
     * @brief Begin a search for files within a directory or for a directory.
     */
    TRANS2_FIND_FIRST2 = 0x0001,

    /**
     * @brief Continue a search for files within a directory or for a
     * directory.
     */
    TRANS2_FIND_NEXT2 = 0x0002,

    /**
     * @brief Request information about a file system on the server.
     */
    TRANS2_QUERY_FS_INFORMATION = 0x0003,

    /**
     * @brief Reserved.
     *
     * @note Not implemented.
     */
    TRANS2_SET_FS_INFORMATION = 0x0004,

    /**
     * @brief Get information about a specific file or directory using a path.
     */
    TRANS2_QUERY_PATH_INFORMATION = 0x0005,

    /**
     * @brief Set the standard and extended attribute information of a specific
     * file or directory using a path.
     */
    TRANS2_SET_PATH_INFORMATION = 0x0006,

    /**
     * @brief Get information about a specific file or directory using a FID.
     */
    TRANS2_QUERY_FILE_INFORMATION = 0x0007,

    /**
     * @brief Set the standard and extended attribute information of a specific
     * file or directory using a FID.
     */
    TRANS2_SET_FILE_INFORMATION = 0x0008,

    /**
     * @brief Reserved.
     *
     * @note Not implemented.
     */
    TRANS2_FSCTL = 0x0009,

    /**
     * @brief Reserved.
     *
     * @note Not implemented.
     */
    TRANS2_IOCTL2 = 0x000A,

    /**
     * @brief Reserved.
     *
     * @note Obselete.
     */
    TRANS2_FIND_NOTIFY_FIRST = 0x000B,

    /**
     * @brief Reserved.
     *
     * @note Obselete.
     */
    TRANS2_FIND_NOTIFY_NEXT = 0x000C,

    /**
     * @brief Create a new directory and optionally set the extended attribute
     * information.
     */
    TRANS2_CREATE_DIRECTORY = 0x000D,

    /**
     * @brief Reserved.
     *
     * @note Not implemented.
     */
    TRANS2_SESSION_SETUP = 0x000E,

    /**
     * @brief Request a DFS referral for a file or directory. See [MS-DFSC] for
     * details.
     */
    TRANS2_GET_DFS_REFERRAL = 0x0010,

    /**
     * @brief Reserved.
     *
     * @note Not implemented.
     */
    TRANS2_REPORT_DFS_INCONSISTENCY = 0x0011,
} smb_trans2_t;

/**
 * @brief Transaction codes used with SMB_COM_NT_TRANSACT.
 */
typedef enum e_smb_nt_trans {
    /**
     * @brief Used to create or open a file or directory when extended
     * attributes (EAs) or a security descriptor (SD) are to be applied.
     */
    NT_TRANSACT_CREATE = 0x0001,

    /**
     * @brief Allows device and file system control functions to be transferred
     * transparently from client to server.
     */
    NT_TRANSACT_IOCTL = 0x0002,

    /**
     * @brief Allows a client to change the security descriptor for a file.
     */
    NT_TRANSACT_SET_SECURITY_DESC  = 0x0003,

    /**
     * @brief Notifies the client when the directory specified by FID is
     * modified. It also returns the names of any files that changed.
     */
    NT_TRANSACT_NOTIFY_CHANGE = 0x0004,

    /**
     * @brief Reserved.
     *
     * @note Not implemented.
     */
    NT_TRANSACT_RENAME = 0x0005,

    /**
     * @brief Allows a client to retrieve the security descriptor for a file.
     */
    NT_TRANSACT_QUERY_SECURITY_DESC = 0x0006,
} smb_nt_trans_t;

#endif /* !__SMB_CIFS_H_ */
