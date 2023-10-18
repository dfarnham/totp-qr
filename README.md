# totp-qr &emsp; [![Latest Version]][crates.io]

[Latest Version]: https://img.shields.io/badge/crates.io-v0.1.0-green
[crates.io]: https://crates.io/crates/totp-qr

# Command line utility to extract otpauth strings from QR-images and generate their respective TOTP

Why? I need the text SECRET encoded in previously saved QR images, screenshots, and Google Authenticator Export images for import into other apps [KeePassXC](https://keepassxc.org), [Proton Pass](https://proton.me/pass)

Mainly I need the SECRET because it's mine, I like CLI, and tools like this might make someone else's day brighter.

This tool uses:

* The excellent [rqrr crate](https://docs.rs/rqrr/latest/rqrr/) for digging out otpauth data from most image types
* The reverse engineered [protobuf](https://alexbakker.me/post/parsing-google-auth-export-qr-code.html)
* The [file-format crate](https://docs.rs/file-format/latest/file_format/) for classifying stdin
* Shout out to [totp-rs](https://docs.rs/totp-rs/latest/totp_rs/) for its succinct byte slicing and **Algorithm Enum**; derivations of both were used. [MIT LICENSE](LICENSE)

<HR>

## Examples
```text
Usage: totp-qr [OPTIONS] [FILES]...

Arguments:
  [FILES]...  image-file|stdin, filename of "-" implies stdin

Options:
  -a, --auth <AUTH>  "otpauth-migration://offline?data=..." or "otpauth://totp/...?secret=SECRET"
  -v, --verbose      verbose output
  -h, --help         Print help
  -V, --version      Print version
```

```text
# Output TOTP, Issuer
$> totp-qr images/*.jpg
237769, Test1
734660, Test2
021109, Test3
237769, Example
```

```text
# Verbose Output
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

```text
# Input an auth link
$> totp-qr --auth="otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
970700, ACME Co
```

```text
# Decode from stdin
$> echo 'secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ' | totp-qr
970700,

$> totp-qr < images/otpauth-migration-qr.jpg
237769, Test1
734660, Test2
021109, Test3j
```

