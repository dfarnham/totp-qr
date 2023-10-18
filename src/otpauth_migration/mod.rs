use crate::totp_token::Account;
use crate::Error;
use base64::{engine::general_purpose, Engine as _};
use protobuf::Message;
mod proto;

/// Convert a Google Authenticator migration QR code string to a list of accounts
pub fn get_accounts(otpauth: &str) -> Result<Vec<Account>, Box<dyn Error>> {
    let data = match otpauth.split("data=").nth(1) {
        Some(data) => urlencoding::decode(data)?.to_string(),
        _ => return Err("No data found in URI".into()),
    };
    let decoded_data = &general_purpose::STANDARD.decode(data)?;
    let migration_payload = proto::google_auth::MigrationPayload::parse_from_bytes(decoded_data)?;
    let alphabet = base32::Alphabet::RFC4648 { padding: false };

    Ok(migration_payload
        .get_otp_parameters()
        .iter()
        .map(|otp| Account {
            secret: base32::encode(alphabet, &otp.secret),
            issuer: match otp.issuer.is_empty() {
                true => otp.name.to_string(),
                false => otp.issuer.to_string(),
            },
            sha: "SHA1".into(),
            digits: match otp.digits {
                2 => 8,
                _ => 6,
            },
            period: 30,
        })
        .collect())
}
