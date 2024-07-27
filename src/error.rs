use crate::utils::{hmac_sha1, SHA1_DIGEST_BYTES};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose, Engine as _};
use rand::distributions::{Alphanumeric, DistString};
use std::fmt;

#[macro_export]
macro_rules! error_report {
    ($expression:expr) => {
        error!("{}:{}", function_name!(), $expression);
    };
}

#[derive(thiserror::Error, Debug)]
pub struct ErrorContext {
    pub timestamp: String,
    pub otp: String,
    pub nonce: String,
    pub sl: String,
    pub error: String,
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "t:{} otp:{} nonce:{} sl:{} error:{}",
            self.timestamp, self.otp, self.nonce, self.sl, self.error
        )
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{}", .0)]
    DB(sqlite::Error),
    #[error("invalid otp")]
    InvalidOTP(Box<ErrorContext>),
    #[error("invalid hotp")]
    InvalidHOTP(Box<ErrorContext>),
    #[error("missing parameter")]
    MissingParameter(Box<ErrorContext>),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let body = match self {
            Self::DB(err) => err.to_string(),
            Self::InvalidOTP(ctx) => {
                let data = format!(
                    "nonce={}&otp={}&sl={}&status={}&t={}",
                    ctx.nonce, ctx.otp, ctx.sl, ctx.error, ctx.timestamp
                );
                let passwd = Alphanumeric.sample_string(&mut rand::thread_rng(), 64);
                let hmac_digest =
                    hmac_sha1(passwd.as_ref(), data.as_bytes()).unwrap_or([0; SHA1_DIGEST_BYTES]);
                let hmac = general_purpose::URL_SAFE.encode(hmac_digest);
                format!(
                    "h={}\r\nt={}\r\notp={}\r\nnonce={}\r\nsl={}\r\nstatus={}\r\n",
                    hmac, ctx.timestamp, ctx.otp, ctx.nonce, ctx.sl, ctx.error
                )
            }
            Self::InvalidHOTP(ctx) => {
                let otp = if ctx.otp.len() > 20 {
                    ctx.otp[..20].into()
                } else {
                    ctx.otp
                };
                format!(
                    "h=\r\nt={}\r\notp={}\r\nstatus={}\r\n",
                    ctx.timestamp, otp, ctx.error
                )
            }
            Self::MissingParameter(ctx) => {
                let data = format!("status={}&t={}", ctx.error, ctx.timestamp);
                let passwd = Alphanumeric.sample_string(&mut rand::thread_rng(), 64);
                let hmac_digest =
                    hmac_sha1(passwd.as_ref(), data.as_bytes()).unwrap_or([0; SHA1_DIGEST_BYTES]);
                let hmac = general_purpose::URL_SAFE.encode(hmac_digest);
                format!(
                    "h={}\r\nt={}\r\nstatus={}\r\n",
                    hmac, ctx.timestamp, ctx.error
                )
            }
        };
        (StatusCode::OK, body).into_response()
    }
}
