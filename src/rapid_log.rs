/// Simplified logging macros that directly use the standard log crate.
/// The standard log macros already check if logging is enabled at the specified level.

#[macro_export]
macro_rules! rapid_debug {
    ($($arg:tt)*) => {
        log::debug!($($arg)*)
    };
}

#[macro_export]
macro_rules! rapid_info {
    ($($arg:tt)*) => {
        log::info!($($arg)*)
    };
}

#[macro_export]
macro_rules! rapid_warn {
    ($($arg:tt)*) => {
        log::warn!($($arg)*)
    };
}

#[macro_export]
macro_rules! rapid_error {
    ($($arg:tt)*) => {
        log::error!($($arg)*)
    };
}

/// Trace level logging for very detailed diagnostics
#[macro_export]
macro_rules! rapid_trace {
    ($($arg:tt)*) => {
        log::trace!($($arg)*)
    };
}
