#![allow(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]

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

// derivative work adopted from:
// https://alexbakker.me/post/parsing-google-auth-export-qr-code.html
// https://github.com/zhangyuan/google-authenticator-extractor/tree/master/src/protos
// https://docs.rs/totp-rs/latest/totp_rs
mod otpauth_migration;
mod totp_token;
use crate::totp_token::Account;

// Display the TOTP token and Account detail
fn display_accounts(
    accinfo: &HashMap<String, Vec<Account>>,
    uri: bool,
    export: bool,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    if uri {
        for otpauth in accinfo.keys() {
            println!("{otpauth}");
        }
    } else if export {
        let acc: Vec<_> = accinfo.values().flatten().collect();
        println!("{}", serde_json::to_string(&acc)?);
    } else {
        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        for (otpauth, accounts) in accinfo {
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

        /// image-files|stdin, filename of "-" implies stdin
        files: Vec<std::path::PathBuf>,
    }
    let args = Args::parse();

    // ===============================================================

    let mut accinfo: HashMap<String, Vec<Account>> = HashMap::new();

    let files = match args.files.is_empty() {
        true => vec![std::path::PathBuf::from("-")],
        false => args.files,
    };

    if let Some(otpauth) = args.auth {
        accinfo.insert(otpauth.clone(), totp_token::get_accounts(&otpauth)?);
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
                accinfo.insert(json.into(), imported_accounts);
            } else {
                // Inspect the bytes to classifying as Image or Text
                let format = FileFormat::from_bytes(&bytes);
                if format.kind() != Kind::Image {
                    for otpauth in std::str::from_utf8(&bytes)?.lines() {
                        accinfo.insert(otpauth.into(), totp_token::get_accounts(otpauth)?);
                    }
                } else {
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
                            accinfo.insert(otpauth.clone(), totp_token::get_accounts(&otpauth)?);
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

    display_accounts(&accinfo, args.uri, args.export, args.verbose)
}

// ===============================================================

#[cfg(test)]
mod test;
