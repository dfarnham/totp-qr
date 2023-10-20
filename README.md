# totp-qr &emsp; [![Latest Version]][crates.io]

[Latest Version]: https://img.shields.io/badge/crates.io-v0.1.1-green
[crates.io]: https://crates.io/crates/totp-qr

# Command line utility to extract otpauth strings from QR-images and generate their respective TOTP

Why? I need the text SECRET encoded in previously saved QR images, screenshots, and Google Authenticator Export images for import into other apps [KeePassXC](https://keepassxc.org), [Proton Pass](https://proton.me/pass)

The motivation for this project was initiated by password housekeeping. I'm content with the tools I use for password management such as [KeePassXC](https://keepassxc.org), [pass](https://www.passwordstore.org/), [iTerm2 Password Manager](https://iterm2.com/features.html) (can't live without now), but I lacked visibility and portability of my TOTP parameters and passwords.

Mainly I need the SECRET because it's mine, I like CLI, and tools like this might make someone else's day brighter.

This tool uses:

* The excellent [rqrr crate](https://docs.rs/rqrr/latest/rqrr/) for digging out otpauth data from most image types
* The reverse engineered [protobuf](https://alexbakker.me/post/parsing-google-auth-export-qr-code.html)
* The [file-format crate](https://docs.rs/file-format/latest/file_format/) for classifying stdin
* Shout out to [totp-rs](https://docs.rs/totp-rs/latest/totp_rs/) for its succinct byte slicing and **Algorithm Enum**; derivations of both were used. [MIT LICENSE](LICENSE)

<HR>

### Project Status:
* Option logic is ugly after adding -i,-e,-u; that'll get refactored next.
* Waiting for resolution on [SIGPIPE](https://github.com/rust-lang/rust/issues/62569) and general CLI Unix tools to avoid "broken pipe".
* The rememdy is to change println!() to writeln!(stdout)? as shown below

```text
pub fn reset_sigpipe() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_family = "unix")]
    {
        use nix::sys::signal;

        unsafe {
            signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigDfl)?;
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // behave like a typical unix utility
    general::reset_sigpipe()?;
    let mut stdout = io::stdout().lock();
    ...
```

<HR>
<HR>

# TOTP-QR

## Using totp-qr in a shell function to securely view tokens

1. Install `totp-qr` e.g. `cargo install totp-qr` or build e.g. `cargo install --path .`
2. Gather your QR-images into a directory
3. Run `scripts/mk-totp-func.sh directory`
4. Inspect, copy, and add to your ~/.bashrc

<HR>

## Creating the shell function, walk-through

### The images directory contains 2 example QRs with encoded otpauth data

1. **otpauth-totp-qr.jpg holds 1 account: "otpauth://totp/..."**
2. **otpauth-migration-qr.jpg holds 3 accounts: "otpauth-migration://offline?data=..."**

```text
$> totp-qr --uri images/otpauth-totp-qr.jpg
otpauth://totp/Example:alice@google.com?issuer=Example&period=30&secret=JBSWY3DPEHPK3PXP

$> totp-qr --uri images/otpauth-migration-qr.jpg
otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA
```
### totp-qr can generate TOTP tokens directly off images but that's not practical
```text
$> totp-qr images/*
083403, Test1
838914, Test2
276913, Test3
083403, Example
```
### otpauth strings hold secrets and algorithm parameters which can be used directly
```text
$> totp-qr --uri images/* | totp-qr
083403, Test1
838914, Test2
276913, Test3
083403, Example
```
### otpauth strings (and images) need to be kept PRIVATE, they contain the SECRET. [OpenSSL](https://www.openssl.org/) can be used to encrypt the otpauth strings
```text
##############################################################
# ** The password shown below "foo" is not actually visible **
##############################################################
$> totp-qr --uri images/* | openssl aes-256-cbc -e -pbkdf2 -a
enter AES-256-CBC encryption password:foo
Verifying - enter AES-256-CBC encryption password:foo

U2FsdGVkX18lfKZ20uQn/AcAWa85hUmcJzQ8mvS9JX0BJb7qVDddrCjbjPxagIw6
hwHeLBPWx1U0GbA7zszAYKNa6FB2I53ldNET/tnutUBNmQeuxqbiVH8A0or9Ni8+
Lj8onivfmaGzcBGGGMtz3wliD/LL+iUhkG+A2FZpIE2mIf9QdwofI9jSAhDhAW3y
d+AXZWWsHRRVs5MvIA++CcchKLG+FOza3fcBIt7RtqkdISQYDw+TgMGLN8NS5/ak
tk8PcuO+QfjmtNXh0/96mn5jYCGdD1NvioeDkwBu7883q2ChHXcOLRuPqqlJAR/2
T+DwgtEyCO5ZhQPn3nj9E1Gy1xXAm+4Yt8CueXvuBS5SJJLQd94Q+HT1SsyMhYB0
FGVb6YifAjV3Snsk3UO/60quJ8cfQxjDW5Pef/a0LjtMZL2d+jaYImFcLEMUrnlI
FRGDcbHR1oAmdonyuSNJBQ==
```
### [scripts/mk-totp-func.sh](scripts/mk-totp-func.sh) automates the creation of a Bash function named totp()
```text
$> ./scripts/mk-totp-func.sh images/
enter AES-256-CBC encryption password:
Verifying - enter AES-256-CBC encryption password:

totp() {
openssl aes-256-cbc -d -pbkdf2 -a << EOF | totp-qr $1 | sort -t, -k2
U2FsdGVkX1+gVAFEnnQVFQVmzDUU47Sl6NIqFOAQaM85dspvn8gt2hueK272RRi4
vdWDBLsFeKM4qp7Jq2TSV2Lca2/29cwPcZtAVnaz02VbxO2m/e3b4RjB9AxjRk1R
iTPdTzG+BO2GYHjdz515Dc/N4+HD5UMVJr7yAsypdJ/ThRN3CWCjUYd3mAGx9/g7
0GCwTJ6psw4CtwbgL3hg66cZq9w43Wwj0P+S3eL87ueZRHHfr10hEtLTsJQLuRDl
479WZpzFFPTyrr3jVQFMqmhgEXKXf2VnFp4aLvCk6OKP93iQU3fE5aRWTEpQytYF
+F/AvpAQUnEOvAAivFFa2SBXZPHDscENzG16P0O8i3hWoyJizoAJIOMOPsA3HgMZ
1kxCFBnME1Pd1dlrSTsfhFNpjfbaURWxI5pwMS/fAKMIoRLWydeGJOukNIv+zPmI
PPJXNNa5fQP647srICuCnw==
EOF
}
```

<HR>
<HR>

### Putting it all together
```text
$> ./scripts/mk-totp-func.sh images/ >> ~/.bashrc
$> . ~/.bashrc
$> type -a totp
totp is a function
totp ()
{
    openssl aes-256-cbc -d -pbkdf2 -a <<EOF |
    ...
EOF
  totp-qr $1 | sort -t, -k2
}
```

### Note: If you're on a Mac using [iTerm2](https://iterm2.com/) check out [password manager](https://iterm2.com/features.html) (shortcut: ⌥ ⌘ F) for supplying passwords

### I use the totp() bash function like this:
```text
$> totp
enter AES-256-CBC decryption password:
757676, Example
757676, Test1
255080, Test2
476239, Test3
```

### View account details as JSON
```text
$> totp -e | jq
enter AES-256-CBC decryption password:
[
  {
    "secret": "JBSWY3DPEHPK3PXP",
    "issuer": "Test1",
    "sha": "SHA1",
    "digits": 6,
    "period": 30
  },
  {
    "secret": "JBSWY3DPEHPK3PXQ",
    "issuer": "Test2",
    "sha": "SHA1",
    "digits": 6,
    "period": 30
  },
  {
    "secret": "JBSWY3DPEHPK3PXR",
    "issuer": "Test3",
    "sha": "SHA1",
    "digits": 6,
    "period": 30
  },
  {
    "secret": "JBSWY3DPEHPK3PXP",
    "issuer": "Example",
    "sha": "SHA1",
    "digits": 6,
    "period": 30
  }
]
```
### Import JSON accounts
```text
$> totp-qr -e images/*.jpg | totp-qr -iv
939954, Account { secret: "JBSWY3DPEHPK3PXP", issuer: "Test1", sha: "SHA1", digits: 6, period: 30 }
561818, Account { secret: "JBSWY3DPEHPK3PXQ", issuer: "Test2", sha: "SHA1", digits: 6, period: 30 }
787732, Account { secret: "JBSWY3DPEHPK3PXR", issuer: "Test3", sha: "SHA1", digits: 6, period: 30 }
939954, Account { secret: "JBSWY3DPEHPK3PXP", issuer: "Example", sha: "SHA1", digits: 6, period: 30 }
```
### View URI's
```text
$> totp -u
enter AES-256-CBC decryption password:
otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA
otpauth://totp/Example:alice@google.com?issuer=Example&period=30&secret=JBSWY3DPEHPK3PXP
```

<HR>
<HR>

## Usage
```text
$> totp-qr -h
Usage: totp-qr [OPTIONS] [FILES]...

Arguments:
  [FILES]...  image-file|stdin, filename of "-" implies stdin

Options:
  -a, --auth <AUTH>  "otpauth-migration://offline?data=..." or "otpauth://totp/...?secret=SECRET"
  -v, --verbose      Verbose output
  -e, --extract      Extract account information as JSON
  -i, --import       Import JSON accounts
  -u, --uri          Output extracted URI's
  -h, --help         Print help
  -V, --version      Print version
```

### Verbose Output
```text
$> totp-qr -v images/*.jpg
otpauth = otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA
237769, Account { secret: "JBSWY3DPEHPK3PXP", issuer: "Test1", sha: "SHA1", digits: 6, period: 30 }
734660, Account { secret: "JBSWY3DPEHPK3PXQ", issuer: "Test2", sha: "SHA1", digits: 6, period: 30 }
021109, Account { secret: "JBSWY3DPEHPK3PXR", issuer: "Test3", sha: "SHA1", digits: 6, period: 30 }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
otpauth = otpauth://totp/Example:alice@google.com?issuer=Example&period=30&secret=JBSWY3DPEHPK3PXP
237769, Account { secret: "JBSWY3DPEHPK3PXP", issuer: "Example", sha: "SHA1", digits: 6, period: 30 }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```
### Input an auth link
```text
$> totp-qr --auth="otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
970700, ACME Co
```
### Decode from stdin
```text
$> echo 'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ' | totp-qr
970700,

$> totp-qr < images/otpauth-migration-qr.jpg
237769, Test1
734660, Test2
021109, Test3
```

