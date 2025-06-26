#[derive(Debug)]
pub enum ErrorCode {
    // Protocol errors (0x0001-0x0100)
    InvalidEventType = 0x01,
    Malformed = 0x02,
    IncompleteMessage = 0x03,
    UnsupportedVersion = 0x04,

    // Application errors (0x0101-0x0200)
    KeyNotFound = 0x11,
    TtlExpired = 0x12,
    ValueTooLarge = 0x13,
    DiskWriteFailed = 0x14,

    // Cluster/State errors (0x0201-0x0300)
    ReadonlyMode = 0x21,
    MasterUnavailable = 0x22,
    SyncDenied = 0x23,

    // System errors (0x0301-0x0400)
    InternalServerError = 0x31,
    ConfigInvalid = 0x32,

    // Client errors (0x0401-0x0500)
    ConnectionFailed = 0x41,
    SendFailed = 0x42,
    NotConnected = 0x43,

    ReadFailed = 0x51,
    WriteFailed = 0x52,
}


#[derive(Debug)]
pub struct Error {
    code: ErrorCode,
    message: Vec<u8>,
}

impl Error {
    pub fn new(code: ErrorCode, message: String) -> Error {
        Error {
            code,
            message: message.into_bytes(),
        }
    }
}
