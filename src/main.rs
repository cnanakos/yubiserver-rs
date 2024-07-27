use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyInit};
use anyhow::Result;
use axum::{
    extract::{Extension, Query},
    response::Html,
    routing::get,
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{SecondsFormat, Utc};
use log::error;
use serde::Deserialize;
use std::{collections::HashMap, fmt, net::SocketAddr, path::PathBuf, sync::Arc};
use stdext::function_name;
use structopt::StructOpt;

mod db;
use db::DB;

mod error;
use error::{Error, ErrorContext};

mod utils;
use utils::hmac_sha1;

mod pool;
use pool::ObjectPool;

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

const OTP_TOKEN_SIZE: usize = 44;
const SQLITE_POOL_CAPACITY: usize = 32;

const YUBIKEY_USER_SELECT_SQL: &str =
    "SELECT yubikeys.nickname,yubikeys.active,yubikeys.aeskey,yubikeys.internalname,yubikeys.counter,\
        yubikeys.time,yubikeys.nonce,apikeys.secret FROM yubikeys JOIN \
        apikeys ON apikeys.nickname=yubikeys.nickname where apikeys.id=?";

const OATH_USER_SELECT_SQL: &str =
    "SELECT oathtokens.nickname,oathtokens.active,oathtokens.counter,oathtokens.secret FROM oathtokens JOIN \
        apikeys ON apikeys.nickname=oathtokens.nickname where apikeys.id=?";

const HOTP_USER_SELECT_SQL: &str =
    "SELECT hotptokens.active,hotptokens.nickname,hotptokens.counter,\
        hotptokens.secret FROM hotptokens JOIN \
        apikeys ON apikeys.nickname=hotptokens.nickname where apikeys.id=?";

const YUBIKEY_COUNTER_UPDATE_SQL: &str =
    "UPDATE yubikeys SET counter=?,time=?,nonce=? WHERE publicname=? AND nickname=? AND counter=? AND time=? and nonce=? AND active='1'";

const OATH_COUNTER_UPDATE_SQL: &str =
    "UPDATE oathtokens SET counter=? WHERE publicname=? AND nickname=? AND counter=? AND active='1'";

const HOTP_COUNTER_UPDATE_SQL: &str =
    "UPDATE hotptokens SET counter=? WHERE nickname=? AND counter=? AND active='1'";

struct YubikeyDbUser {
    active: bool,
    aeskey: String,
    internalname: String,
    counter: i64,
    time: i64,
    nonce: String,
    apisecret: String,
    nickname: String,
}

struct OathDbUser {
    active: bool,
    counter: i64,
    secret: String,
    nickname: String,
}

struct HotpDbUser {
    active: bool,
    nickname: String,
    counter: i64,
    secret: String,
}

#[non_exhaustive]
enum OtpStatus {
    OK,
    BadOtp,
    ReplayedOtp,
    DelayedOtp,
    NoSuchClient,
    BadSignature,
    MissingParameter,
    OperationNotAllowed,
    BackendError,
    _NotEnoughAnswers,
    ReplayedRequest,
    NoAuth,
    InternalError,
}

impl fmt::Display for OtpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OK => "OK",
            Self::BadOtp => "BAD_OTP",
            Self::ReplayedOtp => "REPLAYED_OTP",
            Self::DelayedOtp => "DELAYED_OTP",
            Self::NoSuchClient => "NO_SUCH_CLIENT",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::MissingParameter => "MISSING_PARAMETER",
            Self::OperationNotAllowed => "OPERATION_NOT_ALLOWED",
            Self::BackendError => "BACKEND_ERROR",
            Self::_NotEnoughAnswers => "NOT_ENOUGH_ANSWERS",
            Self::ReplayedRequest => "REPLAYED_REQUEST",
            Self::NoAuth => "NO_AUTH",
            Self::InternalError => "INTERNAL_ERROR",
        })
    }
}

struct HmacResponseContext<'a> {
    session_timestamp: bool,
    session_counter: i64,
    session_token_counter: i64,
    otp_timestamp: i64,
    status: &'a str,
    t: &'a str,
    api_passwd: &'a Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct RequestParams {
    h: Option<String>,
    id: Option<String>,
    sl: Option<String>,
    otp: Option<String>,
    nonce: Option<String>,
    timeout: Option<u64>,
    timestamp: Option<String>,
}

struct ServerContext {
    pool: ObjectPool<DB>,
}

impl ServerContext {
    fn new(db_path: impl Into<PathBuf>) -> Result<Self> {
        let db_path = db_path.into();
        let pool = ObjectPool::new(SQLITE_POOL_CAPACITY, || -> Result<DB> {
            Ok(db::connect(&db_path)?)
        })?;
        Ok(Self { pool })
    }
}

struct Yubiserver<'a> {
    params: &'a RequestParams,
    ctx: Arc<ServerContext>,
}

impl<'a> Yubiserver<'a> {
    fn new(ctx: Arc<ServerContext>, params: &'a RequestParams) -> Result<Self, Error> {
        Ok(Self { params, ctx })
    }

    fn check_crc16_ansi(&self, plaintext: &str) -> Result<bool, OtpStatus> {
        let token = hex::decode(plaintext).map_err(|_| OtpStatus::BadOtp)?;
        let mut crc: u16 = 0xffff; //init
        for t in token.iter() {
            let mut b = *t;
            for _ in 0..8 {
                if ((b ^ (crc as u8)) & 1) > 0 {
                    crc = (crc >> 1) ^ 0x8408; //poly
                } else {
                    crc >>= 1;
                }
                b >>= 1;
            }
        }
        Ok(crc == 0xf0b8) //check
    }

    fn calculate_counter(&self, plaintext: &String) -> Result<i64, OtpStatus> {
        let token = plaintext.as_bytes();
        let mut v = String::new();
        v.push(token[14] as char);
        v.push(token[15] as char);
        v.push(token[12] as char);
        v.push(token[13] as char);
        v.push(token[22] as char);
        v.push(token[23] as char);
        i64::from_str_radix(&v, 16).map_err(|e| {
            error_report!(e);
            OtpStatus::InternalError
        })
    }

    fn calculate_timestamp(&self, plaintext: &String) -> Result<i64, OtpStatus> {
        let token = plaintext.as_bytes();
        let mut v = String::new();
        v.push(token[20] as char);
        v.push(token[21] as char);
        v.push(token[18] as char);
        v.push(token[19] as char);
        v.push(token[16] as char);
        v.push(token[17] as char);
        i64::from_str_radix(&v, 16).map_err(|e| {
            error_report!(e);
            OtpStatus::InternalError
        })
    }

    fn calculate_session_counter(&self, plaintext: &String) -> Result<i64, OtpStatus> {
        let token = plaintext.as_bytes();
        let mut v = String::new();
        v.push(token[14] as char);
        v.push(token[15] as char);
        v.push(token[12] as char);
        v.push(token[13] as char);
        i64::from_str_radix(&v, 16).map_err(|e| {
            error_report!(e);
            OtpStatus::InternalError
        })
    }

    fn calculate_session_token_counter(&self, plaintext: &String) -> Result<i64, OtpStatus> {
        let token = plaintext.as_bytes();
        let mut v = String::new();
        v.push(token[22] as char);
        v.push(token[23] as char);
        i64::from_str_radix(&v, 16).map_err(|e| {
            error_report!(e);
            OtpStatus::InternalError
        })
    }

    fn calculate_hotp(&self, key: &Vec<u8>, i: i64, digits: usize) -> Result<String, OtpStatus> {
        let counter = vec![
            ((i >> 56) & 0xff) as u8,
            ((i >> 48) & 0xff) as u8,
            ((i >> 40) & 0xff) as u8,
            ((i >> 32) & 0xff) as u8,
            ((i >> 24) & 0xff) as u8,
            ((i >> 16) & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            (i & 0xff) as u8,
        ];

        let hmac_digest = hmac_sha1(key.as_slice(), counter.as_slice()).map_err(|e| {
            error_report!(e);
            OtpStatus::BadOtp
        })?;
        let offset = usize::from(hmac_digest[19] & 0xf);
        let bcode: u32 = (u32::from(hmac_digest[offset]) & 0x7f) << 24
            | (u32::from(hmac_digest[offset + 1]) & 0xff) << 16
            | (u32::from(hmac_digest[offset + 2]) & 0xff) << 8
            | u32::from(hmac_digest[offset + 3]) & 0xff;
        let bin_code = format!("{}", bcode);
        if bin_code.len() >= digits {
            Ok(bin_code[bin_code.len() - digits..].to_string())
        } else {
            Ok(bin_code)
        }
    }

    fn validate_hotp(&self) -> Result<String, Error> {
        let otp = match self.params.otp {
            Some(ref otp) => otp,
            None => {
                return Err(Error::MissingParameter(
                    self.err_ctx(OtpStatus::MissingParameter),
                ));
            }
        };

        let user = match self.params.id {
            Some(ref id) => tokio::task::block_in_place(|| {
                self.get_hotp_user(id)
                    .map_err(|e| Error::InvalidHOTP(self.err_ctx(e)))
            })?,
            None => {
                return Err(Error::MissingParameter(
                    self.err_ctx(OtpStatus::MissingParameter),
                ))
            }
        };

        if !user.active {
            return Err(Error::InvalidHOTP(
                self.err_ctx(OtpStatus::OperationNotAllowed),
            ));
        }

        if otp.len() == 6 || otp.len() == 8 {
            let key = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &user.secret)
                .ok_or_else(|| Error::InvalidHOTP(self.err_ctx(OtpStatus::BadOtp)))?;

            for counter in user.counter + 1..user.counter + 256 {
                let tmp = self
                    .calculate_hotp(&key, counter, otp.len())
                    .map_err(|e| Error::InvalidHOTP(self.err_ctx(e)))?;
                if otp.eq(&tmp) {
                    if let Err(err) =
                        tokio::task::block_in_place(|| self.update_hotp_counter(&user, counter))
                    {
                        return Err(Error::InvalidHOTP(self.err_ctx(err)));
                    }
                    return Ok(format!(
                        "h=\r\nt={}\r\notp={}\r\nstatus={}\r\n",
                        self.gen_timestamp(),
                        otp,
                        OtpStatus::OK,
                    ));
                }
            }
            Err(Error::InvalidHOTP(self.err_ctx(OtpStatus::NoAuth)))
        } else {
            Err(Error::InvalidHOTP(self.err_ctx(OtpStatus::BadOtp)))
        }
    }

    fn validate_oath_hotp(&self) -> Result<String, Error> {
        let otp = match self.params.otp {
            Some(ref otp) => otp,
            None => {
                return Err(Error::MissingParameter(
                    self.err_ctx(OtpStatus::MissingParameter),
                ))
            }
        };

        let user = match self.params.id {
            Some(ref id) => tokio::task::block_in_place(|| {
                self.get_oath_user(id)
                    .map_err(|e| Error::InvalidHOTP(self.err_ctx(e)))
            })?,
            None => {
                return Err(Error::MissingParameter(
                    self.err_ctx(OtpStatus::MissingParameter),
                ))
            }
        };

        if !user.active {
            return Err(Error::InvalidHOTP(
                self.err_ctx(OtpStatus::OperationNotAllowed),
            ));
        }

        if otp.len() == 18 || otp.len() == 20 {
            let hotp = &otp[12..];
            if hotp.len() % 2 != 0 {
                return Err(Error::InvalidHOTP(self.err_ctx(OtpStatus::BadOtp)));
            }

            let key = hex::decode(&user.secret).map_err(|e| {
                error_report!(e);
                Error::InvalidHOTP(self.err_ctx(OtpStatus::BadOtp))
            })?;

            for counter in user.counter + 1..user.counter + 256 {
                let tmp = self
                    .calculate_hotp(&key, counter, hotp.len())
                    .map_err(|e| Error::InvalidHOTP(self.err_ctx(e)))?;
                if hotp.eq(&tmp) {
                    if let Err(err) =
                        tokio::task::block_in_place(|| self.update_oath_counter(&user, counter))
                    {
                        return Err(Error::InvalidHOTP(self.err_ctx(err)));
                    }
                    return Ok(format!(
                        "h=\r\nt={}\r\notp={}\r\nstatus={}\r\n",
                        self.gen_timestamp(),
                        otp,
                        OtpStatus::OK
                    ));
                }
            }
            Err(Error::InvalidHOTP(self.err_ctx(OtpStatus::NoAuth)))
        } else {
            Err(Error::InvalidHOTP(self.err_ctx(OtpStatus::BadOtp)))
        }
    }

    fn update_oath_counter(&self, user: &OathDbUser, counter: i64) -> Result<(), OtpStatus> {
        let publicname = self.get_publicid()?;
        let db = self.ctx.pool.get();
        let mut statement = db.prepare(OATH_COUNTER_UPDATE_SQL).map_err(|e| {
            error_report!(e);
            OtpStatus::BackendError
        })?;

        statement.bind((1, counter)).unwrap();
        statement.bind((2, publicname)).unwrap();
        statement.bind((3, user.nickname.as_str())).unwrap();
        statement.bind((4, user.counter)).unwrap();
        match statement.next() {
            Ok(sqlite::State::Done) => Ok(()),
            Ok(sqlite::State::Row) => {
                error_report!("oath counter update statement returned a row");
                Err(OtpStatus::BackendError)
            }
            Err(err) => {
                error_report!(err);
                Err(OtpStatus::BackendError)
            }
        }
    }

    fn update_hotp_counter(&self, user: &HotpDbUser, counter: i64) -> Result<(), OtpStatus> {
        let db = self.ctx.pool.get();
        let mut statement = db.prepare(HOTP_COUNTER_UPDATE_SQL).map_err(|e| {
            error_report!(e);
            OtpStatus::BackendError
        })?;

        statement.bind((1, counter)).unwrap();
        statement.bind((2, user.nickname.as_str())).unwrap();
        statement.bind((3, user.counter)).unwrap();
        match statement.next() {
            Ok(sqlite::State::Done) => Ok(()),
            Ok(sqlite::State::Row) => {
                error_report!("hotp counter update statement returned a row");
                Err(OtpStatus::BackendError)
            }
            Err(err) => {
                error_report!(err);
                Err(OtpStatus::BackendError)
            }
        }
    }

    fn validate_otp(&self) -> Result<String, Error> {
        if self.params.otp.is_none() {
            return Err(Error::MissingParameter(
                self.err_ctx(OtpStatus::MissingParameter),
            ));
        }

        let nonce = match self.params.nonce {
            Some(ref nonce) => {
                if nonce.len() < 16 || nonce.len() > 40 {
                    return Err(Error::MissingParameter(
                        self.err_ctx(OtpStatus::MissingParameter),
                    ));
                } else {
                    nonce
                }
            }
            None => {
                return Err(Error::MissingParameter(
                    self.err_ctx(OtpStatus::MissingParameter),
                ));
            }
        };

        let user = match self.params.id {
            Some(ref id) => tokio::task::block_in_place(|| -> Result<_, Error> {
                self.get_yubikey_user(id)
                    .map_err(|e| Error::InvalidOTP(self.err_ctx(e)))
            })?,
            None => {
                return Err(Error::MissingParameter(
                    self.err_ctx(OtpStatus::MissingParameter),
                ))
            }
        };

        if !user.active {
            return Err(Error::InvalidOTP(
                self.err_ctx(OtpStatus::OperationNotAllowed),
            ));
        }

        let api_passwd = general_purpose::STANDARD
            .decode(&user.apisecret)
            .map_err(|e| {
                error_report!(e);
                Error::InvalidOTP(self.err_ctx(OtpStatus::InternalError))
            })?;

        if let Some(ref h) = self.params.h {
            let hmac_req = match self.calculate_hmac_request(&api_passwd) {
                Ok(h) => Ok(h),
                Err(err) => Err(Error::InvalidOTP(self.err_ctx(err))),
            }?;

            if !h.eq(&hmac_req) {
                return Err(Error::MissingParameter(
                    self.err_ctx(OtpStatus::BadSignature),
                ));
            }
        }

        let plaintext = self
            .aes128ecb_decrypt(&user)
            .map_err(|e| Error::InvalidOTP(self.err_ctx(e)))?;

        if !user.internalname.eq(&plaintext[..12]) {
            return Err(Error::InvalidOTP(self.err_ctx(OtpStatus::BadOtp)));
        }

        if let Err(err) = self.check_crc16_ansi(&plaintext) {
            return Err(Error::InvalidOTP(self.err_ctx(err)));
        }

        let otp_counter = self
            .calculate_counter(&plaintext)
            .map_err(|e| Error::InvalidOTP(self.err_ctx(e)))?;

        let otp_timestamp = self
            .calculate_timestamp(&plaintext)
            .map_err(|e| Error::InvalidOTP(self.err_ctx(e)))?;

        if (user.time == otp_timestamp)
            && ((user.counter >> 8) == (otp_counter >> 8))
            && user.nonce.eq(nonce)
        {
            return Err(Error::InvalidOTP(self.err_ctx(OtpStatus::ReplayedRequest)));
        }

        if user.counter >= otp_counter {
            return Err(Error::InvalidOTP(self.err_ctx(OtpStatus::ReplayedOtp)));
        }

        if (user.time >= otp_timestamp) && ((user.counter >> 8) == (otp_counter >> 8)) {
            return Err(Error::InvalidOTP(self.err_ctx(OtpStatus::DelayedOtp)));
        }

        if let Err(err) = tokio::task::block_in_place(|| {
            self.update_yubikey_countertimestampnonce(&user, otp_counter, otp_timestamp, nonce)
        }) {
            return Err(Error::InvalidOTP(self.err_ctx(err)));
        }

        let mut session_timestamp = false;
        let mut session_counter: i64 = 0;
        let mut session_token_counter: i64 = 0;
        match self.params.timestamp {
            Some(ref timestamp) if timestamp == "1" => {
                session_counter = self
                    .calculate_session_counter(&plaintext)
                    .map_err(|e| Error::InvalidOTP(self.err_ctx(e)))?;
                session_token_counter = self
                    .calculate_session_token_counter(&plaintext)
                    .map_err(|e| Error::InvalidOTP(self.err_ctx(e)))?;
                session_timestamp = true;
            }
            _ => {}
        };

        let t = self.gen_timestamp();
        let status = OtpStatus::OK.to_string();
        let hmac = self
            .calculate_hmac_response(&HmacResponseContext {
                session_timestamp,
                session_counter,
                session_token_counter,
                otp_timestamp,
                status: &status,
                t: &t,
                api_passwd: &api_passwd,
            })
            .map_err(|e| Error::InvalidOTP(self.err_ctx(e)))?;

        if session_timestamp {
            Ok(format!(
                "h={}\r\nt={}\r\notp={}\r\nnonce={}\r\nsl={}\r\n\
                        timestamp={}\r\nsessioncounter={}\r\nsessionuse={}\r\n\
                        status={}\r\n",
                hmac,
                t,
                self.params.otp.as_ref().unwrap(),
                nonce,
                self.get_sl(),
                otp_timestamp,
                session_counter,
                session_token_counter,
                status,
            ))
        } else {
            Ok(format!(
                "h={}\r\nt={}\r\notp={}\r\nnonce={}\r\nsl={}\r\nstatus={}\r\n",
                hmac,
                t,
                self.params.otp.as_ref().unwrap(),
                nonce,
                self.get_sl(),
                status,
            ))
        }
    }

    fn gen_timestamp(&self) -> String {
        Utc::now()
            .to_rfc3339_opts(SecondsFormat::Millis, true)
            .to_string()
    }

    fn get_otp_in_hex(&self) -> Result<String, OtpStatus> {
        let otp = match self.params.otp {
            Some(ref otp) => otp,
            None => {
                return Err(OtpStatus::BadOtp);
            }
        };

        if otp.len() != OTP_TOKEN_SIZE {
            return Err(OtpStatus::BadOtp);
        }
        self.modhex_to_hex(otp.trim())
    }

    fn modhex_to_hex(&self, s: &str) -> Result<String, OtpStatus> {
        let mut res_str = String::new();
        let mh2h: HashMap<char, char> = [
            ('c', '0'),
            ('f', '4'),
            ('j', '8'),
            ('r', 'c'),
            ('b', '1'),
            ('g', '5'),
            ('k', '9'),
            ('t', 'd'),
            ('d', '2'),
            ('h', '6'),
            ('l', 'a'),
            ('u', 'e'),
            ('e', '3'),
            ('i', '7'),
            ('n', 'b'),
            ('v', 'f'),
        ]
        .iter()
        .cloned()
        .collect();

        for c in s.chars() {
            match mh2h.get(&c) {
                Some(x) => res_str.push(*x),
                None => return Err(OtpStatus::BadOtp),
            }
        }
        Ok(res_str)
    }

    fn get_publicid(&self) -> Result<&'a str, OtpStatus> {
        let otp = match self.params.otp {
            Some(ref otp) => otp,
            None => {
                return Err(OtpStatus::MissingParameter);
            }
        };

        if otp.len() < 12 {
            return Err(OtpStatus::BadOtp);
        }
        Ok(otp[..12].into())
    }

    fn get_yubikey_user(&self, id: &str) -> Result<YubikeyDbUser, OtpStatus> {
        let db = self.ctx.pool.get();
        let mut statement = db.prepare(YUBIKEY_USER_SELECT_SQL).map_err(|e| {
            error_report!(e);
            OtpStatus::BackendError
        })?;

        statement.bind((1, id)).unwrap();
        match statement.next() {
            Ok(sqlite::State::Done) => Err(OtpStatus::NoSuchClient),
            Ok(sqlite::State::Row) => {
                let nickname = statement.read::<String, _>("nickname").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let active = statement.read::<String, _>("active").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let aeskey = statement.read::<String, _>("aeskey").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let internalname = statement.read::<String, _>("internalname").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let counter = statement.read::<i64, _>("counter").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let time = statement.read::<i64, _>("time").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let nonce = statement.read::<String, _>("nonce").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let apisecret = statement.read::<String, _>("secret").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;

                let active = active.eq("1");
                Ok(YubikeyDbUser {
                    nickname,
                    active,
                    aeskey,
                    internalname,
                    counter,
                    time,
                    nonce,
                    apisecret,
                })
            }
            Err(e) => {
                error_report!(e);
                Err(OtpStatus::BackendError)
            }
        }
    }

    fn get_oath_user(&self, id: &str) -> Result<OathDbUser, OtpStatus> {
        let db = self.ctx.pool.get();
        let mut statement = db.prepare(OATH_USER_SELECT_SQL).map_err(|e| {
            error_report!(e);
            OtpStatus::BackendError
        })?;

        statement.bind((1, id)).unwrap();
        match statement.next() {
            Ok(sqlite::State::Done) => Err(OtpStatus::NoSuchClient),
            Ok(sqlite::State::Row) => {
                let active = statement.read::<String, _>("active").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let counter = statement.read::<i64, _>("counter").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let secret = statement.read::<String, _>("secret").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let nickname = statement.read::<String, _>("nickname").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;

                let active = active.eq("1");
                Ok(OathDbUser {
                    active,
                    counter,
                    secret,
                    nickname,
                })
            }
            Err(e) => {
                error_report!(e);
                Err(OtpStatus::BackendError)
            }
        }
    }

    fn get_hotp_user(&self, id: &str) -> Result<HotpDbUser, OtpStatus> {
        let db = self.ctx.pool.get();
        let mut statement = db.prepare(HOTP_USER_SELECT_SQL).map_err(|e| {
            error_report!(e);
            OtpStatus::BackendError
        })?;

        statement.bind((1, id)).unwrap();
        match statement.next() {
            Ok(sqlite::State::Done) => Err(OtpStatus::NoSuchClient),
            Ok(sqlite::State::Row) => {
                let active = statement.read::<String, _>("active").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let nickname = statement.read::<String, _>("nickname").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let counter = statement.read::<i64, _>("counter").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;
                let secret = statement.read::<String, _>("secret").map_err(|e| {
                    error_report!(e);
                    OtpStatus::BackendError
                })?;

                let active = active.eq("1");
                Ok(HotpDbUser {
                    active,
                    nickname,
                    counter,
                    secret,
                })
            }
            Err(e) => {
                error_report!(e);
                Err(OtpStatus::BackendError)
            }
        }
    }

    fn update_yubikey_countertimestampnonce(
        &self,
        user: &YubikeyDbUser,
        counter: i64,
        timestamp: i64,
        nonce: &str,
    ) -> Result<(), OtpStatus> {
        let publicname = self.get_publicid()?;
        let db = self.ctx.pool.get();
        let mut statement = db.prepare(YUBIKEY_COUNTER_UPDATE_SQL).map_err(|e| {
            error_report!(e);
            OtpStatus::BackendError
        })?;

        statement.bind((1, counter)).unwrap();
        statement.bind((2, timestamp)).unwrap();
        statement.bind((3, nonce)).unwrap();
        statement.bind((4, publicname)).unwrap();
        statement.bind((5, user.nickname.as_str())).unwrap();
        statement.bind((6, user.counter)).unwrap();
        statement.bind((7, user.time)).unwrap();
        statement.bind((8, user.nonce.as_str())).unwrap();
        match statement.next() {
            Ok(sqlite::State::Done) => Ok(()),
            Ok(sqlite::State::Row) => {
                error_report!("counter/timestamp/nonce update statement returned a row");
                Err(OtpStatus::BackendError)
            }
            Err(e) => {
                error_report!(e);
                Err(OtpStatus::BackendError)
            }
        }
    }

    fn aes128ecb_decrypt(&self, user: &YubikeyDbUser) -> Result<String, OtpStatus> {
        let hex_otp = self.get_otp_in_hex()?;
        let aes_key_hex = hex::decode(&user.aeskey).map_err(|e| {
            error_report!(e);
            OtpStatus::BadOtp
        })?;

        let token = hex::decode(&hex_otp[12..]).map_err(|e| {
            error_report!(e);
            OtpStatus::BadOtp
        })?;

        let mut buf = [0u8; 32];
        let pt = Aes128EcbDec::new(aes_key_hex.as_slice().into())
            .decrypt_padded_b2b_mut::<NoPadding>(token.as_slice(), &mut buf)
            .map_err(|e| {
                error_report!(e);
                OtpStatus::BadOtp
            })?;
        let plaintext = hex::encode(pt);
        Ok(plaintext)
    }

    fn get_sl(&self) -> &str {
        match self.params.sl {
            Some(ref sl) => {
                if sl != "-1" {
                    sl
                } else {
                    "100"
                }
            }
            None => "-1",
        }
    }

    fn calculate_hmac_request(&self, password: &[u8]) -> Result<String, OtpStatus> {
        let mut data = String::new();
        if let Some(ref id) = self.params.id {
            data.push_str(&format!("id={}", id));
        }

        if let Some(ref nonce) = self.params.nonce {
            data.push_str(&format!("&nonce={}", nonce));
        }

        if let Some(ref otp) = self.params.otp {
            data.push_str(&format!("&otp={}", otp));
        }

        if let Some(ref sl) = self.params.sl {
            if sl != "-1" {
                data.push_str(&format!("&sl={}", sl));
            } else {
                data.push_str("&sl=100");
            }
        }

        if let Some(ref timeout) = self.params.timeout {
            data.push_str(&format!("&timeout={}", timeout));
        }

        if let Some(ref timestamp) = self.params.timestamp {
            data.push_str(&format!("&timestamp={}", timestamp));
        }

        let hmac_digest = hmac_sha1(password, data.as_bytes()).map_err(|e| {
            error_report!(e);
            OtpStatus::InternalError
        })?;

        Ok(general_purpose::URL_SAFE.encode(hmac_digest))
    }

    fn calculate_hmac_response(&self, ctx: &HmacResponseContext) -> Result<String, OtpStatus> {
        let mut data = String::new();
        if ctx.session_timestamp {
            data.push_str(&format!(
                "nonce={}&otp={}&sessioncounter={}&sessionuse={}&sl={}&status={}&t={}&timestamp={}",
                self.params.nonce.as_ref().unwrap(),
                self.params.otp.as_ref().unwrap(),
                ctx.session_counter,
                ctx.session_token_counter,
                self.get_sl(),
                ctx.status,
                ctx.t,
                ctx.otp_timestamp
            ));
        } else {
            data.push_str(&format!(
                "nonce={}&otp={}&sl={}&status={}&t={}",
                self.params.nonce.as_ref().unwrap(),
                self.params.otp.as_ref().unwrap(),
                self.get_sl(),
                ctx.status,
                ctx.t
            ));
        }

        let hmac_digest = hmac_sha1(ctx.api_passwd, data.as_bytes()).map_err(|e| {
            error_report!(e);
            OtpStatus::InternalError
        })?;

        Ok(general_purpose::URL_SAFE.encode(hmac_digest))
    }

    fn err_ctx(&self, err: OtpStatus) -> Box<ErrorContext> {
        let nonce = match self.params.nonce {
            Some(ref nonce) => {
                if nonce.len() < 16 || nonce.len() > 40 {
                    " "
                } else {
                    nonce
                }
            }
            None => " ",
        };
        ErrorContext {
            sl: self.get_sl().into(),
            otp: self.params.otp.clone().unwrap_or_default(),
            error: err.to_string(),
            nonce: nonce.into(),
            timestamp: self.gen_timestamp(),
        }
        .into()
    }
}

async fn root() -> Html<&'static str> {
    Html(
        "Yubico Yubikey:<br><form \
         action='/wsapi/2.0/verify' method='GET'> \
         <input type='text' name='otp'><br><input
         type='submit'></form><br>OATH/HOTP
         tokens:<br> \
         <form action='/wsapi/2.0/oauthverify' method='GET'> \
         <input type='text' name='otp'><br><input
         type='submit'></form>",
    )
}

async fn verify_handler(
    Extension(ctx): Extension<Arc<ServerContext>>,
    Query(params): Query<RequestParams>,
) -> Result<String, Error> {
    Yubiserver::new(ctx, &params)?.validate_otp()
}

async fn oauth_hotp_verify_handler(
    Extension(ctx): Extension<Arc<ServerContext>>,
    Query(params): Query<RequestParams>,
) -> Result<String, Error> {
    Yubiserver::new(ctx, &params)?.validate_oath_hotp()
}

async fn hotp_verify_handler(
    Extension(ctx): Extension<Arc<ServerContext>>,
    Query(params): Query<RequestParams>,
) -> Result<String, Error> {
    Yubiserver::new(ctx, &params)?.validate_hotp()
}

#[derive(StructOpt)]
#[structopt(
    name = "yubiserver",
    about = "Yubikey OTP and HOTP/OATH validation server"
)]
struct Opt {
    /// Defines the database path we should use.
    #[structopt(short, long, parse(from_os_str))]
    db: PathBuf,

    /// Defines the socket addr on which we should listen to.
    #[structopt(short, long, default_value = "127.0.0.1:3000")]
    listen_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();
    let opt = Opt::from_args();
    let ctx = Arc::new(ServerContext::new(opt.db)?);
    let app = Router::new()
        .route("/", get(root))
        .route("/wsapi/2.0/verify", get(verify_handler))
        .route("/wsapi/2.0/oauthverify", get(oauth_hotp_verify_handler))
        .route("/wsapi/2.0/hotpverify", get(hotp_verify_handler))
        .layer(Extension(ctx));

    axum::Server::bind(&opt.listen_addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
