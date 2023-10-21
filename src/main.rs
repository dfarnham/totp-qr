//! # totp-qr
//!
//! ### Command line utility to extract otpauth strings from QR-images and generate their respective TOTP
//!
//! Why? I need the text SECRET encoded in previously saved QR images, screenshots, and Google Authenticator Export images for import into other apps [KeePassXC](https://keepassxc.org), [Proton Pass](https://proton.me/pass)
//!
//! The motivation for this project was initiated by password housekeeping. I'm content with the tools I use for password management such as [KeePassXC](https://keepassxc.org), [pass](https://www.passwordstore.org/), [iTerm2 Password Manager](https://iterm2.com/features.html) (can't live without now), but I lacked visibility and portability of my TOTP parameters and passwords.
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
//! ## Project Status:
//!
//! * Waiting for resolution on [SIGPIPE](https://github.com/rust-lang/rust/issues/62569) for general CLI Unix tools to avoid "broken pipe".
//! * The rememdy is to change println!() to writeln!(stdout)? as shown below
//!
//! ```text
//! pub fn reset_sigpipe() -> Result<(), Box<dyn std::error::Error>> {
//!     #[cfg(target_family = "unix")]
//!     {
//!         use nix::sys::signal;
//!
//!         unsafe {
//!             signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigDfl)?;
//!         }
//!     }
//!
//!     Ok(())
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // behave like a typical unix utility
//!     general::reset_sigpipe()?;
//!     let mut stdout = io::stdout().lock();
//! ```
//!
//! <HR>
//! <HR>
//!
//! # TOTP-QR
//!
//! ## Using totp-qr in a shell function to securely view tokens
//!
//! 1. Install `totp-qr` e.g. `cargo install totp-qr` or build e.g. `cargo install --path .`
//! 2. Gather your QR-images into a directory
//! 3. Run `scripts/mk-totp-func.sh directory`
//! 4. Inspect, copy, and add to your ~/.bashrc
//!
//! <HR>
//!
//! # Creating the shell function, walk-through
//!
//! ### The images directory contains 2 example QRs
//!
//! 1. **otpauth-totp-qr.jpg holds 1 account: "otpauth://totp/..."**
//! 2. **otpauth-migration-qr.jpg holds 3 accounts: "otpauth-migration://offline?data=..."**
//!
//! ```text
//! $> totp-qr --uri images/otpauth-totp-qr.jpg
//! otpauth://totp/Example:alice@google.com?issuer=Example&period=30&secret=JBSWY3DPEHPK3PXP
//!
//! $> totp-qr --uri images/otpauth-migration-qr.jpg
//! otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA
//! ```
//! ### otpauth data should be kept PRIVATE, [OpenSSL](https://www.openssl.org/) can be used to encrypt the data (password: foo)
//! ```text
//! $> totp-qr --uri images/* | openssl aes-256-cbc -e -pbkdf2 -a
//! enter AES-256-CBC encryption password:
//! Verifying - enter AES-256-CBC encryption password:
//!
//! U2FsdGVkX18lfKZ20uQn/AcAWa85hUmcJzQ8mvS9JX0BJb7qVDddrCjbjPxagIw6
//! hwHeLBPWx1U0GbA7zszAYKNa6FB2I53ldNET/tnutUBNmQeuxqbiVH8A0or9Ni8+
//! Lj8onivfmaGzcBGGGMtz3wliD/LL+iUhkG+A2FZpIE2mIf9QdwofI9jSAhDhAW3y
//! d+AXZWWsHRRVs5MvIA++CcchKLG+FOza3fcBIt7RtqkdISQYDw+TgMGLN8NS5/ak
//! tk8PcuO+QfjmtNXh0/96mn5jYCGdD1NvioeDkwBu7883q2ChHXcOLRuPqqlJAR/2
//! T+DwgtEyCO5ZhQPn3nj9E1Gy1xXAm+4Yt8CueXvuBS5SJJLQd94Q+HT1SsyMhYB0
//! FGVb6YifAjV3Snsk3UO/60quJ8cfQxjDW5Pef/a0LjtMZL2d+jaYImFcLEMUrnlI
//! FRGDcbHR1oAmdonyuSNJBQ==
//! ```
//! ### [scripts/mk-totp-func.sh](scripts/mk-totp-func.sh) encrypts URI's and outputs a Bash function named totp()
//! ```text
//! $> ./scripts/mk-totp-func.sh images/
//! enter AES-256-CBC encryption password:
//! Verifying - enter AES-256-CBC encryption password:
//!
//! totp() {
//! openssl aes-256-cbc -d -pbkdf2 -a << EOF | totp-qr $1 | sort -t, -k2
//! U2FsdGVkX1+gVAFEnnQVFQVmzDUU47Sl6NIqFOAQaM85dspvn8gt2hueK272RRi4
//! vdWDBLsFeKM4qp7Jq2TSV2Lca2/29cwPcZtAVnaz02VbxO2m/e3b4RjB9AxjRk1R
//! iTPdTzG+BO2GYHjdz515Dc/N4+HD5UMVJr7yAsypdJ/ThRN3CWCjUYd3mAGx9/g7
//! 0GCwTJ6psw4CtwbgL3hg66cZq9w43Wwj0P+S3eL87ueZRHHfr10hEtLTsJQLuRDl
//! 479WZpzFFPTyrr3jVQFMqmhgEXKXf2VnFp4aLvCk6OKP93iQU3fE5aRWTEpQytYF
//! +F/AvpAQUnEOvAAivFFa2SBXZPHDscENzG16P0O8i3hWoyJizoAJIOMOPsA3HgMZ
//! 1kxCFBnME1Pd1dlrSTsfhFNpjfbaURWxI5pwMS/fAKMIoRLWydeGJOukNIv+zPmI
//! PPJXNNa5fQP647srICuCnw==
//! EOF
//! }
//! ```
//!
//! <HR>
//! <HR>
//!
//! ### Putting it all together
//! ```text
//! $> ./scripts/mk-totp-func.sh images/ >> ~/.bashrc
//! $> . ~/.bashrc
//! $> type -a totp
//! totp is a function
//! totp ()
//! {
//!     openssl aes-256-cbc -d -pbkdf2 -a <<EOF |
//!     ...
//! EOF
//!   totp-qr $1 | sort -t, -k2
//! }
//! ```
//! ### Note: If you're on a Mac using [iTerm2](https://iterm2.com/) check out [password manager](https://iterm2.com/features.html) (shortcut: ⌥ ⌘ F) for supplying passwords
//!
//! ### totp() displays tokens sorted by issuer
//! ```text
//! $> totp
//! enter AES-256-CBC decryption password:
//! 757676, Example
//! 757676, Test1
//! 255080, Test2
//! 476239, Test3
//! ```
//! ### totp -e to view account details as JSON
//! ```text
//! $> totp -e | jq
//! enter AES-256-CBC decryption password:
//! [
//!   {
//!     "secret": "JBSWY3DPEHPK3PXP",
//!     "issuer": "Test1",
//!     "sha": "SHA1",
//!     "digits": 6,
//!     "period": 30
//!   },
//!   {
//!     "secret": "JBSWY3DPEHPK3PXQ",
//!     "issuer": "Test2",
//!     "sha": "SHA1",
//!     "digits": 6,
//!     "period": 30
//!   },
//!   {
//!     "secret": "JBSWY3DPEHPK3PXR",
//!     "issuer": "Test3",
//!     "sha": "SHA1",
//!     "digits": 6,
//!     "period": 30
//!   },
//!   {
//!     "secret": "JBSWY3DPEHPK3PXP",
//!     "issuer": "Example",
//!     "sha": "SHA1",
//!     "digits": 6,
//!     "period": 30
//!   }
//! ]
//! ```
//! ### totp -u to view URI's
//! ```text
//! $> totp -u
//! enter AES-256-CBC decryption password:
//! otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA
//! otpauth://totp/Example:alice@google.com?issuer=Example&period=30&secret=JBSWY3DPEHPK3PXP
//! ```
//!
//! <HR>
//! <HR>
//!
//! ## General Usage
//! ```text
//! Usage: totp-qr [OPTIONS] [FILES]...
//!
//! Arguments:
//!   [FILES]...  image-file|stdin, filename of "-" implies stdin
//!
//! Options:
//!   -a, --auth <AUTH>  "otpauth-migration://offline?data=..." or "otpauth://totp/...?secret=SECRET"
//!   -v, --verbose      Verbose output
//!   -e, --export       Export account information as JSON
//!   -i, --import       Import JSON accounts
//!   -u, --uri          Output extracted URI's
//!   -h, --help         Print help
//!   -V, --version      Print version
//! ```
//!
//! ### Verbose Output (-v, --verbose)
//! ```text
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
//! ### Auth link (-a, --auth)
//! ```text
//! $> totp-qr --auth="otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
//! 970700, ACME Co
//! ```
//! ### Decode from stdin
//! ```text
//! $> echo 'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ' | totp-qr
//! 970700,
//!
//! $> totp-qr < images/otpauth-migration-qr.jpg
//! 237769, Test1
//! 734660, Test2
//! 021109, Test3
//! ```
//! ### Import (-i, --import) / export (-e, --export) JSON Accounts
//! ```text
//! $> totp-qr -e images/*.jpg | totp-qr -iv
//! 939954, Account { secret: "JBSWY3DPEHPK3PXP", issuer: "Test1", sha: "SHA1", digits: 6, period: 30 }
//! 561818, Account { secret: "JBSWY3DPEHPK3PXQ", issuer: "Test2", sha: "SHA1", digits: 6, period: 30 }
//! 787732, Account { secret: "JBSWY3DPEHPK3PXR", issuer: "Test3", sha: "SHA1", digits: 6, period: 30 }
//! 939954, Account { secret: "JBSWY3DPEHPK3PXP", issuer: "Example", sha: "SHA1", digits: 6, period: 30 }
//! ```

// ===============================================================

use anyhow::{Context, Result};
use clap::Parser;
use file_format::{FileFormat, Kind};
use image::io::Reader as ImageReader;
use rqrr::PreparedImage;
use std::collections::HashMap;
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
use crate::totp_token::Account;

// Display the TOTP token and Account detail
fn display_accounts(
    otpauths: &HashMap<String, Vec<Account>>,
    time: Option<u64>,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    let time = match time {
        Some(time) => time,
        None => SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };

    for (otpauth, accounts) in otpauths.iter() {
        if verbose && otpauth.starts_with("otpauth") {
            println!("otpauth = {otpauth}");
        }
        for account in accounts {
            let token = totp_token::time_token(time, account)?;
            if verbose {
                println!("{token}, {account:?}");
            } else {
                println!("{token}, {}", account.issuer);
            }
        }
        if verbose {
            println!("{:~^40}", "");
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    #[derive(Parser, Debug)]
    #[clap(author, version, about)]
    struct Args {
        /// "otpauth-migration://offline?data=..." or "otpauth://totp/...?secret=SECRET"
        #[arg(short, long)]
        auth: Option<String>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Export account information as JSON
        #[arg(short, long)]
        export: bool,

        /// Import JSON accounts
        #[arg(short, long)]
        import: bool,

        /// Output account URI's
        #[arg(short, long)]
        uri: bool,

        /// image-file|stdin, filename of "-" implies stdin
        files: Vec<std::path::PathBuf>,
    }
    let args = Args::parse();

    // ===============================================================

    let mut accounts: HashMap<String, Vec<Account>> = HashMap::new();

    let files = match args.files.is_empty() {
        true => vec![std::path::PathBuf::from("-")],
        false => args.files,
    };

    if let Some(otpauth) = args.auth {
        accounts.insert(otpauth.clone(), totp_token::get_accounts(&otpauth)?);
    } else {
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

            if args.import {
                let json = std::str::from_utf8(&bytes)?;
                let imported_accounts: Vec<Account> =
                    serde_json::from_str(json).with_context(|| "serde: Deserializing JSON into Vec<Account>")?;
                accounts.insert(json.into(), imported_accounts);
            } else {
                // inspect the bytes to classifying as Image or Text
                let format = FileFormat::from_bytes(&bytes);
                if format.kind() != Kind::Image {
                    for otpauth in std::str::from_utf8(&bytes)?.lines() {
                        accounts.insert(otpauth.into(), totp_token::get_accounts(otpauth)?);
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
                            accounts.insert(otpauth.clone(), totp_token::get_accounts(&otpauth)?);
                        }
                        grids => eprintln!(
                            "Skipping {input_name}, expected 1 image grid, found {} grids",
                            grids.len()
                        ),
                    }
                }
            }
        }
    }

    if args.uri {
        for otpauth in accounts.keys() {
            println!("{otpauth}");
        }
    } else if args.export {
        let acc: Vec<_> = accounts.values().flatten().collect();
        println!("{}", serde_json::to_string(&acc)?);
    } else {
        let time = None; // SystemTime::now()
        display_accounts(&accounts, time, args.verbose)?;
    }

    Ok(())
}

// ===============================================================

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

    #[test]
    fn test_export_json() -> Result<(), Box<dyn Error>> {
        let otpauth = "otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA";
        let json = r#"[{"secret":"JBSWY3DPEHPK3PXP","issuer":"Test1","sha":"SHA1","digits":6,"period":30},{"secret":"JBSWY3DPEHPK3PXQ","issuer":"Test2","sha":"SHA1","digits":6,"period":30},{"secret":"JBSWY3DPEHPK3PXR","issuer":"Test3","sha":"SHA1","digits":6,"period":30}]"#;
        let accounts = totp_token::get_accounts(otpauth)?;

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
        assert_eq!(json, serde_json::to_string(&accounts)?);

        Ok(())
    }

    #[test]
    fn test_import_json() -> Result<(), Box<dyn Error>> {
        let json = r#"[{"secret":"JBSWY3DPEHPK3PXP","issuer":"Test1","sha":"SHA1","digits":6,"period":30},{"secret":"JBSWY3DPEHPK3PXQ","issuer":"Test2","sha":"SHA1","digits":6,"period":30},{"secret":"JBSWY3DPEHPK3PXR","issuer":"Test3","sha":"SHA1","digits":6,"period":30}]"#;
        let accounts: Vec<Account> = serde_json::from_str(json)?;

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

        Ok(())
    }
}
