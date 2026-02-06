use std::{collections::HashMap, net::TcpStream};

// All STARS definitions
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const CONFIG_FILE: &str = "./stars.cfg";
pub const DEFAULT_LIBDIR: &str = "takaserv-lib";

pub const TCP_BUFFER_SIZE: usize = 4096;
pub const READ_TIMEOUT: u64 = 2000; // timeout in msec
pub const RNDMAX: u16 = 10000;

pub const HOST_LIST: &str = "allow.cfg";
pub const ALIASES: &str = "aliases.cfg";
pub const CMD_DENY: &str = "command_deny.cfg";
pub const CMD_ALLOW: &str = "command_allow.cfg";
pub const RECONNECT_TABLE_DENY: &str = "reconnectable_deny.cfg";
pub const RECONNECT_TABLE_ALLOW: &str = "reconnectable_allow.cfg";
pub const SHUTDOWN_ALLOW: &str = "shutdown_allow.cfg";

// Type definitions
pub type NodeList = HashMap<String, TcpStream>;
pub type GenericError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type GenericResult<T> = Result<T, GenericError>;

// Macros
#[macro_export]
macro_rules! dbprint { // To print messages only in debug build
    ($($args:tt)*) => {
        #[cfg(debug_assertions)]
        {
            let msg = format!("[DEBUG] {:#?}", $($args)*);
            println!("{}", msg)
        }
    };
}

#[macro_export]
macro_rules! lazy_static { //to replace the lazy_static create
    ($( $(#[$a:meta])* $v:vis static ref $i:ident : $t:ty = $e:expr ; )+) => {
        $(
            $(#[$a])* $v static $i: ::std::sync::LazyLock<$t> = ::std::sync::LazyLock::new(|| $e);
        )+
    };
}
