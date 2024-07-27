use std::path::Path;
pub type DB = sqlite::ConnectionThreadSafe;

pub fn connect(db_path: impl AsRef<Path>) -> Result<DB, crate::Error> {
    sqlite::Connection::open_thread_safe_with_flags(
        db_path,
        sqlite::OpenFlags::new().with_read_write(),
    )
    .map_err(crate::Error::DB)
}
