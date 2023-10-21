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
