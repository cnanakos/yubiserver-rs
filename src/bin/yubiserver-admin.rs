use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{SecondsFormat, Utc};
use clap::{builder::TypedValueParser, error::ErrorKind, Args, Parser, Subcommand};
use rand::distributions::{Alphanumeric, DistString};
use std::{
    fmt,
    path::{Path, PathBuf},
};

enum DBTable {
    Yubikey,
    Oath,
    Hotp,
    Api,
}

impl fmt::Display for DBTable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DBTable::Yubikey => write!(f, "yubikeys"),
            DBTable::Oath => write!(f, "oathtokens"),
            DBTable::Hotp => write!(f, "hotptokens"),
            DBTable::Api => write!(f, "apikeys"),
        }
    }
}

#[derive(Debug, Parser)]
#[clap(subcommand_required = true)]
struct Cli {
    #[clap(short, long)]
    /// Define the database path we should use.
    db: PathBuf,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Copy, Clone, Debug)]
struct StringSizeValueParser {
    size: usize,
    eq_lt: bool,
}

impl StringSizeValueParser {
    fn new(size: usize, eq_lt: bool) -> Self {
        Self { size, eq_lt }
    }
}

impl TypedValueParser for StringSizeValueParser {
    type Value = String;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value
            .to_str()
            .ok_or_else(|| clap::Error::new(ErrorKind::InvalidUtf8).with_cmd(cmd))?;
        if self.eq_lt {
            if value.len() != self.size {
                let arg = arg
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "...".to_owned());
                let err_msg = format!(
                    "invalid value size '{}' for '{arg}', should be equal to {}\n",
                    value.len(),
                    self.size
                );
                return Err(clap::Error::raw(ErrorKind::ValueValidation, err_msg).with_cmd(cmd));
            }
        } else if value.len() > self.size {
            let arg = arg
                .map(|a| a.to_string())
                .unwrap_or_else(|| "...".to_owned());
            let err_msg = format!(
                "invalid value size '{}' for '{arg}', should be less than {}\n",
                value.len(),
                self.size
            );
            return Err(clap::Error::raw(ErrorKind::ValueValidation, err_msg).with_cmd(cmd));
        }
        Ok(value.to_owned())
    }
}

#[derive(Args, Debug)]
struct AddOTPArgs {
    #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
    /// username where this Yubikey OTP is attached to.
    username: String,
    #[clap(short, long, value_parser = StringSizeValueParser::new(12, true))]
    /// Public Token ID (must be 12 characters long)
    public_id: String,
    #[clap(short, long, value_parser = StringSizeValueParser::new(12, true))]
    /// Secret ID (must be 12 characters long)
    secret_id: String,
    #[clap(short, long, value_parser = StringSizeValueParser::new(32, true))]
    /// AES key (must be 32 characters long)
    aes_key: String,
}

#[derive(Args, Debug)]
struct AddOATHArgs {
    #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
    /// username where this Yubikey OTP is attached to.
    username: String,
    #[clap(short, long, value_parser = StringSizeValueParser::new(12, true))]
    /// Public Token ID (must be 12 characters long)
    public_id: String,
    #[clap(short, long, value_parser = StringSizeValueParser::new(40, true))]
    /// Secret ID (must be 40 characters long)
    secret_id: String,
}

#[derive(Args, Debug)]
struct AddHOTPArgs {
    #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
    /// username where this Yubikey OTP is attached to.
    username: String,
    #[clap(short, long)]
    /// Secret Key (must be in plaintext)
    secret_key: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Handle Yubikey tokens
    Yubikey(YubikeyCommand),
    /// Handle OATH-HOTP tokens
    Oath(OathCommand),
    /// Handle HOTP tokens
    Hotp(HotpCommand),
    /// Handle API keys
    Api(ApiCommand),
}

#[derive(Debug, Args)]
struct YubikeyCommand {
    #[clap(subcommand)]
    command: YubikeySubCommand,
}

#[derive(Debug, Args)]
struct OathCommand {
    #[clap(subcommand)]
    command: OathSubCommand,
}

#[derive(Debug, Args)]
struct HotpCommand {
    #[clap(subcommand)]
    command: HotpSubCommand,
}

#[derive(Debug, Args)]
struct ApiCommand {
    #[clap(subcommand)]
    command: ApiSubCommand,
}

#[derive(Debug, Subcommand)]
enum YubikeySubCommand {
    /// Add Yubikey OTP user
    Add(AddOTPArgs),
    /// Delete Yubikey OTP user
    Delete {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to delete
        username: String,
    },
    /// Enable Yubikey OTP user
    Enable {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to enable
        username: String,
    },
    /// Disable Yubikey OTP user
    Disable {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to disable
        username: String,
    },
    /// List all Yubikey users
    List,
}

#[derive(Debug, Subcommand)]
enum OathSubCommand {
    /// Add OATH user
    Add(AddOATHArgs),
    /// Delete OATH user
    Delete {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to delete
        username: String,
    },
    /// Enable OATH user
    Enable {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to enable
        username: String,
    },
    /// Disable OATH user
    Disable {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to disable
        username: String,
    },
    /// List all OATH users
    List,
}

#[derive(Debug, Subcommand)]
enum HotpSubCommand {
    /// Add HOTP user
    Add(AddHOTPArgs),
    /// Delete HOTP user
    Delete {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to delete
        username: String,
    },
    /// Enable HOTP user
    Enable {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to enable
        username: String,
    },
    /// Disable HOTP user
    Disable {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to disable
        username: String,
    },
    /// List all HOTP users
    List,
}

#[derive(Debug, Subcommand)]
enum ApiSubCommand {
    /// Add API user
    Add {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to add
        username: String,
    },
    /// Delete API user
    Delete {
        #[clap(short, long, value_parser = StringSizeValueParser::new(16, false))]
        /// username to delete
        username: String,
    },
    /// List all API users
    List,
}

struct YubiserverCli {
    table: DBTable,
    db: sqlite::Connection,
}

impl YubiserverCli {
    fn new(db_path: impl AsRef<Path>, table: DBTable) -> Result<Self> {
        let db = match sqlite::Connection::open_with_flags(
            db_path,
            sqlite::OpenFlags::new().with_read_write(),
        ) {
            Ok(db) => Ok(db),
            Err(err) => Err(anyhow!("{err}")),
        }?;
        Ok(Self { table, db })
    }

    fn create_statement<'a, 'b: 'a>(&'b self, query: &'a str) -> Result<sqlite::Statement<'a>> {
        match self.db.prepare(query) {
            Ok(st) => Ok(st),
            Err(err) => Err(anyhow!("{err}")),
        }
    }

    fn db_get_value(&self, statement: &sqlite::Statement, value: &str) -> Result<String> {
        match statement.read::<String, _>(value) {
            Ok(v) => Ok(v),
            Err(err) => Err(anyhow!("{err}")),
        }
    }

    fn finduser(&self, username: &str) -> Result<bool> {
        let db_table = self.table.to_string();
        let query = format!("SELECT * FROM {db_table} WHERE nickname='{username}'");
        let mut statement = self.create_statement(&query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => Ok(false),
            Ok(sqlite::State::Row) => Ok(true),
            Err(err) => Err(anyhow!("{err}")),
        }
    }

    fn findapiuser(&self, username: &str) -> Result<bool> {
        let query = format!("SELECT id FROM apikeys WHERE nickname='{username}'");
        let mut statement = self.create_statement(&query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => Ok(false),
            Ok(sqlite::State::Row) => Ok(true),
            Err(err) => Err(anyhow!("{err}")),
        }
    }

    fn finduser_publicname(&self, username: &str, publicname: &str) -> Result<bool> {
        let db_table = self.table.to_string();
        let query = format!(
            "SELECT * FROM {db_table} WHERE nickname='{username}' OR publicname='{publicname}'"
        );
        let mut statement = self.create_statement(&query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => Ok(false),
            Ok(sqlite::State::Row) => Ok(true),
            Err(err) => Err(anyhow!("{err}")),
        }
    }

    fn find_next_apikeys_id(&self) -> Result<i64> {
        let query = "SELECT id from apikeys ORDER BY id DESC LIMIT 1";
        let mut statement = self.create_statement(query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => Ok(1_i64),
            Ok(sqlite::State::Row) => {
                let id = self.db_get_value(&statement, "id")?;
                match id.parse::<i64>() {
                    Ok(i) => Ok(i + 1),
                    Err(e) => Err(anyhow!("{e}")),
                }
            }
            Err(err) => Err(anyhow!("{err}")),
        }
    }

    fn yubikey_add(&self, args: &AddOTPArgs) -> Result<()> {
        if !self.findapiuser(&args.username)? {
            bail!("user '{}' doesn't have an API key", args.username,);
        }

        if self.finduser_publicname(&args.username, &args.public_id)? {
            bail!(
                "user '{}' or/and public ID '{}' already exist",
                args.username,
                args.public_id
            );
        }

        let timestamp = Utc::now()
            .to_rfc3339_opts(SecondsFormat::Millis, true)
            .to_string();
        let query = format!(
            "INSERT INTO yubikeys VALUES('{}','{}','{}','{}','{}',1,1,1, '')",
            args.username, args.public_id, timestamp, args.secret_id, args.aes_key
        );
        let mut statement = self.create_statement(&query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => {
                println!("user '{}' has been added", args.username);
            }
            Ok(sqlite::State::Row) => {
                bail!("insert statement returned a row");
            }
            Err(err) => {
                bail!("{err}");
            }
        }
        Ok(())
    }

    fn oath_add(&self, args: &AddOATHArgs) -> Result<()> {
        if !self.findapiuser(&args.username)? {
            bail!("user '{}' doesn't have an API key", args.username,);
        }
        if self.finduser_publicname(&args.username, &args.public_id)? {
            bail!(
                "user '{}' or/and public ID '{}' already exist",
                args.username,
                args.public_id
            );
        }

        let timestamp = Utc::now()
            .to_rfc3339_opts(SecondsFormat::Millis, true)
            .to_string();

        let query = format!(
            "INSERT INTO oathtokens VALUES('{}','{}','{}','{}',1,1)",
            args.username, args.public_id, timestamp, args.secret_id,
        );

        let mut statement = self.create_statement(&query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => {
                println!("user '{}' has been added", args.username);
            }
            Ok(sqlite::State::Row) => {
                bail!("insert statement returned a row");
            }
            Err(err) => {
                bail!("{err}");
            }
        }
        Ok(())
    }

    fn hotp_add(&self, args: &AddHOTPArgs) -> Result<()> {
        if !self.findapiuser(&args.username)? {
            bail!("user '{}' doesn't have an API key", args.username,);
        }
        if self.finduser(&args.username)? {
            bail!("user '{}' already exist", args.username,);
        }

        let timestamp = Utc::now()
            .to_rfc3339_opts(SecondsFormat::Millis, true)
            .to_string();

        let secret_key = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            args.secret_key.as_bytes(),
        );

        let query = format!(
            "INSERT INTO hotptokens VALUES('{}','{}','{}',1,1)",
            args.username, timestamp, secret_key,
        );

        let mut statement = self.create_statement(&query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => {
                println!("user '{}' has been added", args.username);
            }
            Ok(sqlite::State::Row) => {
                bail!("insert statement returned a row");
            }
            Err(err) => {
                bail!("{err}");
            }
        }
        Ok(())
    }

    fn delete(&self, username: &str) -> Result<()> {
        if !self.finduser(username)? {
            bail!("user '{username}' doesn't exist");
        }

        let db_table = self.table.to_string();
        let query = format!("DELETE FROM {db_table} WHERE nickname='{username}'");

        let mut statement = self.create_statement(&query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => {
                println!("user '{username}' has been deleted");
            }
            Ok(sqlite::State::Row) => {
                bail!("delete statement returned a row");
            }
            Err(err) => {
                bail!("{err}");
            }
        }
        Ok(())
    }

    fn control(&self, username: &str, active: bool) -> Result<()> {
        let db_table = self.table.to_string();
        if !self.finduser(username)? {
            bail!("user '{username}' doesn't exist");
        }

        let query_active = match active {
            true => 1,
            false => 0,
        };

        let query = match self.table {
            DBTable::Yubikey | DBTable::Oath | DBTable::Hotp => {
                format!("UPDATE {db_table} SET active='{query_active}' WHERE nickname='{username}'")
            }
            DBTable::Api => {
                bail!("API table not supported");
            }
        };

        let mut statement = self.create_statement(&query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => {
                if active {
                    println!("user '{username}' has been activated");
                } else {
                    println!("user '{username}' has been deactivated");
                }
            }
            Ok(sqlite::State::Row) => {
                bail!("update statement returned a row");
            }
            Err(err) => {
                bail!("{err}");
            }
        }
        Ok(())
    }

    fn list(&self) -> Result<()> {
        let db_table = self.table.to_string();
        let query = match self.table {
            DBTable::Yubikey | DBTable::Oath => {
                format!("SELECT nickname,publicname,active from {db_table}")
            }
            DBTable::Hotp => format!("SELECT nickname,active from {db_table}"),
            DBTable::Api => format!("SELECT nickname,id from {db_table}"),
        };
        let mut statement = self.create_statement(&query)?;

        match self.table {
            DBTable::Yubikey | DBTable::Oath => {
                println!(
                    "{0: <20} | {1: <20} | {2: <20}",
                    "[Username]", "[Public Token ID]", "[Active]"
                );
            }
            DBTable::Hotp => {
                println!("{0: <20} | {1: <20}", "[Username]", "[Active]");
            }
            DBTable::Api => {
                println!("{0: <20} | {1: <20}", "[Username]", "[API ID]");
            }
        }
        let mut rows = 0;
        match self.table {
            DBTable::Yubikey | DBTable::Oath => {
                while let Ok(sqlite::State::Row) = statement.next() {
                    let nickname = self.db_get_value(&statement, "nickname")?;
                    let publicid = self.db_get_value(&statement, "publicname")?;
                    let active = self.db_get_value(&statement, "active")?;
                    println!("{0: <20} | {1: <20} | {2: <20}", nickname, publicid, active);
                    rows += 1;
                }
            }
            DBTable::Hotp => {
                while let Ok(sqlite::State::Row) = statement.next() {
                    let nickname = self.db_get_value(&statement, "nickname")?;
                    let active = self.db_get_value(&statement, "active")?;
                    println!("{0: <20} | {1: <20}", nickname, active);
                    rows += 1;
                }
            }
            DBTable::Api => {
                while let Ok(sqlite::State::Row) = statement.next() {
                    let nickname = self.db_get_value(&statement, "nickname")?;
                    let id = self.db_get_value(&statement, "id")?;
                    println!("{0: <20} | {1: <20}", nickname, id);
                    rows += 1;
                }
            }
        }
        if rows == 0 {
            println!("No keys found in database");
        } else {
            println!("Total keys in database: {rows}");
        }
        Ok(())
    }

    fn api_add(&self, username: &str) -> Result<()> {
        if self.finduser(username)? {
            bail!("user '{username}' already exists");
        }

        let nextid = self.find_next_apikeys_id()?;
        let key = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        let b64_key = general_purpose::STANDARD.encode(key);
        let query = format!(
            "INSERT INTO apikeys VALUES('{}','{}','{}')",
            username, b64_key, nextid,
        );

        let mut statement = self.create_statement(&query)?;
        match statement.next() {
            Ok(sqlite::State::Done) => {
                println!("New API key for '{}' is: {}", username, b64_key);
                println!("API key ID for '{}' is: {}", username, nextid);
            }
            Ok(sqlite::State::Row) => {
                bail!("insert statement returned a row");
            }
            Err(err) => {
                bail!("{err}");
            }
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::Yubikey(cmd)) => {
            let yc = YubiserverCli::new(cli.db, DBTable::Yubikey)?;
            let YubikeyCommand { command } = &cmd;
            match command {
                YubikeySubCommand::Add(args) => yc.yubikey_add(args),
                YubikeySubCommand::Delete { username } => yc.delete(username),
                YubikeySubCommand::Enable { username } => yc.control(username, true),
                YubikeySubCommand::Disable { username } => yc.control(username, false),
                YubikeySubCommand::List => yc.list(),
            }?;
        }
        Some(Commands::Hotp(cmd)) => {
            let yc = YubiserverCli::new(cli.db, DBTable::Hotp)?;
            let HotpCommand { command } = &cmd;
            match command {
                HotpSubCommand::Add(args) => yc.hotp_add(args),
                HotpSubCommand::Delete { username } => yc.delete(username),
                HotpSubCommand::Enable { username } => yc.control(username, true),
                HotpSubCommand::Disable { username } => yc.control(username, false),
                HotpSubCommand::List => yc.list(),
            }?;
        }
        Some(Commands::Oath(cmd)) => {
            let yc = YubiserverCli::new(cli.db, DBTable::Oath)?;
            let OathCommand { command } = &cmd;
            match command {
                OathSubCommand::Add(args) => yc.oath_add(args),
                OathSubCommand::Delete { username } => yc.delete(username),
                OathSubCommand::Enable { username } => yc.control(username, true),
                OathSubCommand::Disable { username } => yc.control(username, false),
                OathSubCommand::List => yc.list(),
            }?;
        }
        Some(Commands::Api(cmd)) => {
            let yc = YubiserverCli::new(cli.db, DBTable::Api)?;
            let ApiCommand { command } = &cmd;
            match command {
                ApiSubCommand::Add { username } => yc.api_add(username),
                ApiSubCommand::Delete { username } => yc.delete(username),
                ApiSubCommand::List => yc.list(),
            }?;
        }
        None => {}
    }
    Ok(())
}
