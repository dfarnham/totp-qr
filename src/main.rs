//! # totp-qr
//!
//! ### Command line utility to extract otpauth strings from QR-images and generate their respective TOTP
//!
//! `Why?` I need the text SECRET encoded in previously saved QR images, screenshots, and Google Authenticator
//! Export images for import into other apps [KeePassXC](https://keepassxc.org), [Proton Pass](https://proton.me/pass)
//!
//! Mainly I need the SECRET because it's mine, I like CLI, and tools like this might make someone else's day brighter.
//!
//! This tool uses:
//!
//! * The excellent [rqrr crate](https://docs.rs/rqrr/latest/rqrr/) for digging out otpauth data from most image types
//!
//! * The reverse engineered [protobuf](https://alexbakker.me/post/parsing-google-auth-export-qr-code.html)
//!
//! * The [file-format crate](https://docs.rs/file-format/latest/file_format/) for classifying stdin
//!
//! * Shout out to [totp-rs](https://docs.rs/totp-rs/latest/totp_rs/) for its succinct byte slicing
//! and `Algorithm Enum`; derivations of both were used. [MIT LICENSE](LICENSE)
//!
//! # Examples
//!
//! ```text
//! # Output TOTP, Issuer
//! $> totp-qr images/*.jpg
//! 237769, Test1
//! 734660, Test2
//! 021109, Test3
//! 237769, Example
//! ```
//!
//! ```text
//! # Verbose Output
//! $> totp-qr -v images/*.jpg
//! otpauth = otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA
//! 237769, Account { secret: "JBSWY3DPEHPK3PXP", issuer: "Test1", sha: "SHA1", digits: 6, period: 30 }
//! 734660, Account { secret: "JBSWY3DPEHPK3PXQ", issuer: "Test2", sha: "SHA1", digits: 6, period: 30 }
//! 021109, Account { secret: "JBSWY3DPEHPK3PXR", issuer: "Test3", sha: "SHA1", digits: 6, period: 30 }
//! ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//! otpauth = otpauth://totp/Example:alice@google.com?issuer=Example&period=30&secret=JBSWY3DPEHPK3PXP
//! 237769, Account { secret: "JBSWY3DPEHPK3PXP", issuer: "Example", sha: "SHA1", digits: 6, period: 30 }
//! ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//! ```
//!
//! ```text
//! # Input an auth link
//! $> totp-qr --auth="otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
//! 970700, ACME Co
//! ```
//!
//! ```text
//! # Decode from stdin
//! $> echo 'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ' | totp-qr
//! 970700,
//!
//! $> totp-qr < images/otpauth-migration-qr.jpg
//! 237769, Test1
//! 734660, Test2
//! 021109, Test3
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use file_format::{FileFormat, Kind};
use image::io::Reader as ImageReader;
use rqrr::PreparedImage;
use std::error::Error;
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::time::{SystemTime, UNIX_EPOCH};

// adopted from:
// https://alexbakker.me/post/parsing-google-auth-export-qr-code.html
// https://github.com/zhangyuan/google-authenticator-extractor/tree/master/src/protos
mod otpauth_migration;

// derivative:
// https://docs.rs/totp-rs/latest/totp_rs
mod totp_token;

// Display the TOTP token and Account detail
fn display_accounts(otpauth: &str, time: Option<u64>, verbose: bool) -> Result<(), Box<dyn Error>> {
    let time = match time {
        Some(time) => time,
        None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };

    if verbose {
        println!("otpauth = {otpauth}");
    }
    for account in totp_token::get_accounts(otpauth)? {
        let token = totp_token::time_token(time, &account)?;
        if verbose {
            println!("{token}, {account:?}");
        } else {
            println!("{token}, {}", account.issuer);
        }
    }
    if verbose {
        println!("{:~^40}", "");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    #[derive(Parser, Debug)]
    #[clap(
        author,
        version,
        about,
    )]
    struct Args {
        /// "otpauth-migration://offline?data=..." or "otpauth://totp/...?secret=SECRET"
        #[arg(short, long)]
        auth: Option<String>,

        /// verbose output
        #[arg(short, long)]
        verbose: bool,

        /// image-file|stdin, filename of "-" implies stdin
        files: Vec<std::path::PathBuf>,
    }
    let args = Args::parse();

    // ===============================================================

    // -a, --auth
    if let Some(otpauth) = args.auth {
        let time = None; // SystemTime::now()
        display_accounts(&otpauth, time, args.verbose)?;
        return Ok(());
    }

    let files = match args.files.is_empty() {
        true => vec![std::path::PathBuf::from("-")],
        false => args.files,
    };

    for file in files {
        // Read stdin|file into a byte buffer, note a filename of "-" implies stdin
        let mut bytes = vec![];
        let input_name: String = match file.as_os_str() != "-" {
            true => {
                File::open(&file)
                    .with_context(|| format!("could not open file `{:?}`", file.as_os_str()))?
                    .read_to_end(&mut bytes)
                    .with_context(|| format!("could not read file `{:?}`", file.as_os_str()))?;
                file.to_string_lossy().into()
            }
            false => {
                io::stdin()
                    .read_to_end(&mut bytes)
                    .with_context(|| "could not read `stdin`")?;
                "<stdin>".into()
            }
        };

        // inspect the bytes to classifying as Image or Text
        let format = FileFormat::from_bytes(&bytes);
        if format.kind() != Kind::Image {
            // Text
            for otpauth in std::str::from_utf8(&bytes)?.lines() {
                let time = None; // SystemTime::now()
                display_accounts(otpauth, time, args.verbose)?;
            }
        } else {
            // Image
            // Detect the image format and decode the bytes into a Luma image
            let img = ImageReader::new(Cursor::new(bytes))
                .with_guessed_format()?
                .decode()?
                .to_luma8();

            // Prepare for detection
            let mut img = PreparedImage::prepare(img);

            // Search for grids, without decoding
            match img.detect_grids() {
                grids if grids.len() == 1 => {
                    // Decode the grid and obtain the otpauth string
                    // e.g. otpauth://totp/Site:User?Secret=Base-32&period=30&digits=6&issuer=SiteName
                    // e.g. otpauth-migration://offline?data=Base-64
                    let (_meta, otpauth) = grids[0].decode()?;
                    let time = None; // SystemTime::now()
                    display_accounts(&otpauth, time, args.verbose)?;
                }
                grids => eprintln!(
                    "\n** Error({input_name}) expected 1 image grid, found {} grids **\n",
                    grids.len()
                ),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp_token::Account;

    // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    #[test]
    fn test_totp() -> Result<(), Box<dyn Error>> {
        let time = 1697590260;
        let otpauth = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30";
        let accounts = totp_token::get_accounts(otpauth)?;
        assert_eq!(accounts.len(), 1);

        assert_eq!(
            accounts,
            [Account {
                secret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ".to_string(),
                issuer: "ACME Co".to_string(),
                sha: "SHA1".to_string(),
                digits: 6,
                period: 30
            }]
        );

        for second in 0..30 {
            let token = totp_token::time_token(time + second, &accounts[0])?;
            assert_eq!(token, "064946");
        }

        Ok(())
    }

    #[test]
    fn test_migration() -> Result<(), Box<dyn Error>> {
        let time = 1697590260;
        let otpauth = "otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA";

        let accounts = totp_token::get_accounts(otpauth)?;
        assert_eq!(accounts.len(), 3);

        assert_eq!(
            accounts,
            [
                Account {
                    secret: "JBSWY3DPEHPK3PXP".to_string(),
                    issuer: "Test1".to_string(),
                    sha: "SHA1".to_string(),
                    digits: 6,
                    period: 30
                },
                Account {
                    secret: "JBSWY3DPEHPK3PXQ".to_string(),
                    issuer: "Test2".to_string(),
                    sha: "SHA1".to_string(),
                    digits: 6,
                    period: 30
                },
                Account {
                    secret: "JBSWY3DPEHPK3PXR".to_string(),
                    issuer: "Test3".to_string(),
                    sha: "SHA1".to_string(),
                    digits: 6,
                    period: 30
                }
            ]
        );

        for second in 0..30 {
            let token = totp_token::time_token(time + second, &accounts[0])?;
            assert_eq!(token, "055815");

            let token = totp_token::time_token(time + second, &accounts[1])?;
            assert_eq!(token, "362314");

            let token = totp_token::time_token(time + second, &accounts[2])?;
            assert_eq!(token, "236718");
        }

        Ok(())
    }
}
