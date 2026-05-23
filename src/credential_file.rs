// This code is part of Qiskit.
//
// (C) Copyright IBM 2026
//
// This code is licensed under the Apache License, Version 2.0. You may
// obtain a copy of this license in the LICENSE.txt file in the root directory
// of this source tree or at http://www.apache.org/licenses/LICENSE-2.0.
//
// Any modifications or derivative works of this code must retain this
// copyright notice, and modified files need to carry a notice indicating
// that they have been altered from the originals.

use serde::Deserialize;
use std::fs;
use std::os::unix::fs::MetadataExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialFileError {
    #[error("failed to read credential file {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("invalid credential file {path}: {source}")]
    Json {
        path: String,
        source: serde_json::Error,
    },
    #[error("missing required field '{field}' for resource type '{resource_type}'")]
    MissingField {
        field: &'static str,
        resource_type: String,
    },
    #[error("credential file {path} has unsafe permissions {mode:#o}, expected 0o400")]
    InsecurePermissions { path: String, mode: u32 },
    #[error("credential file {path} is not owned by the current process user")]
    WrongOwner { path: String },
    #[error("unsupported credential file version '{got}', expected '1'")]
    UnsupportedVersion { got: String },
}

#[derive(Debug, Deserialize)]
pub struct CredentialFile {
    pub version: String,
    pub resource_name: String,
    pub resource_type: String,
    pub endpoint: Option<String>,
    pub service_crn: Option<String>,
    pub access_token: String,
    pub token_expires_at: Option<String>,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_access_key_id: Option<String>,
    pub s3_secret_access_key: Option<String>,
}

pub struct IbmCredentials {
    pub endpoint: String,
    pub service_crn: String,
    pub access_token: String,
    pub token_expires_at: Option<String>,
    pub s3_endpoint: String,
    pub s3_bucket: String,
    pub s3_region: String,
    pub s3_access_key_id: String,
    pub s3_secret_access_key: String,
}

pub struct PasqalCredentials {
    pub access_token: String,
    pub token_expires_at: Option<String>,
}

impl CredentialFile {
    /// Load and validate a credential file from `path`.
    ///
    /// Checks:
    /// 1. File metadata is readable.
    /// 2. Permissions are exactly 0o400 — SPANK always writes 0400; any other
    ///    mode means tampering or non-SPANK write.
    /// 3. Owner uid matches the current process effective uid.
    /// 4. File contents can be read and parsed as JSON.
    /// 5. Version field equals "1".
    pub fn from_path(path: &str) -> Result<Self, CredentialFileError> {
        let meta = fs::metadata(path).map_err(|e| CredentialFileError::Io {
            path: path.to_string(),
            source: e,
        })?;

        // SPANK always writes 0400; any other mode means tampering or non-SPANK write.
        let mode = meta.mode() & 0o777;
        if mode != 0o400 {
            return Err(CredentialFileError::InsecurePermissions {
                path: path.to_string(),
                mode,
            });
        }

        // Safety: geteuid() is always safe to call.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(CredentialFileError::WrongOwner {
                path: path.to_string(),
            });
        }

        let contents = fs::read_to_string(path).map_err(|e| CredentialFileError::Io {
            path: path.to_string(),
            source: e,
        })?;

        let creds: CredentialFile =
            serde_json::from_str(&contents).map_err(|e| CredentialFileError::Json {
                path: path.to_string(),
                source: e,
            })?;

        if creds.version != "1" {
            return Err(CredentialFileError::UnsupportedVersion {
                got: creds.version.clone(),
            });
        }

        Ok(creds)
    }

    /// Check for `{resource_name}_QRMI_CREDENTIAL_FILE` in the environment.
    ///
    /// Returns `Ok(None)` when the env var is not set (non-SPANK callers fall
    /// through to the existing individual-env-var path unchanged).
    /// Returns `Ok(Some(creds))` when set and the file loads successfully.
    /// Returns `Err(...)` when set but the file cannot be loaded.
    pub fn from_env(resource_name: &str) -> Result<Option<Self>, CredentialFileError> {
        let key = format!("{}_QRMI_CREDENTIAL_FILE", resource_name);
        match std::env::var(&key) {
            Err(_) => Ok(None),
            Ok(path) => Self::from_path(&path).map(Some),
        }
    }

    /// Extract and validate IBM Quantum System credentials.
    ///
    /// All S3 and service fields are required and must be non-empty.
    pub fn ibm_credentials(self) -> Result<IbmCredentials, CredentialFileError> {
        let resource_type = self.resource_type.clone();

        let require = |val: Option<String>, field: &'static str| -> Result<String, CredentialFileError> {
            match val {
                Some(s) if !s.is_empty() => Ok(s),
                _ => Err(CredentialFileError::MissingField {
                    field,
                    resource_type: resource_type.clone(),
                }),
            }
        };

        let endpoint = require(self.endpoint, "endpoint")?;
        let service_crn = require(self.service_crn, "service_crn")?;
        let s3_endpoint = require(self.s3_endpoint, "s3_endpoint")?;
        let s3_bucket = require(self.s3_bucket, "s3_bucket")?;
        let s3_region = require(self.s3_region, "s3_region")?;
        let s3_access_key_id = require(self.s3_access_key_id, "s3_access_key_id")?;
        let s3_secret_access_key = require(self.s3_secret_access_key, "s3_secret_access_key")?;

        Ok(IbmCredentials {
            endpoint,
            service_crn,
            access_token: self.access_token,
            token_expires_at: self.token_expires_at,
            s3_endpoint,
            s3_bucket,
            s3_region,
            s3_access_key_id,
            s3_secret_access_key,
        })
    }

    /// Extract and validate PASQAL Cloud credentials.
    ///
    /// `access_token` must be non-empty.
    pub fn pasqal_credentials(self) -> Result<PasqalCredentials, CredentialFileError> {
        if self.access_token.is_empty() {
            return Err(CredentialFileError::MissingField {
                field: "access_token",
                resource_type: self.resource_type,
            });
        }
        Ok(PasqalCredentials {
            access_token: self.access_token,
            token_expires_at: self.token_expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::Permissions;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    const IBM_JSON: &str = r#"{
        "version": "1",
        "resource_name": "test_heron",
        "resource_type": "ibm-quantum-system",
        "endpoint": "https://quantum.example.com",
        "service_crn": "crn:v1:bluemix:public:...",
        "access_token": "Bearer eyJhbGci...",
        "token_expires_at": "2026-05-20T16:30:00Z",
        "s3_endpoint": "https://s3.us-east.cloud-object-storage.appdomain.cloud",
        "s3_bucket": "my-results-bucket",
        "s3_region": "us-east",
        "s3_access_key_id": "abc123",
        "s3_secret_access_key": "xyz789"
    }"#;

    const PASQAL_JSON: &str = r#"{
        "version": "1",
        "resource_name": "FRESNEL",
        "resource_type": "pasqal-cloud",
        "access_token": "<pasqal-auth0-token>",
        "token_expires_at": null
    }"#;

    fn write_temp_file_with_mode(content: &str, mode: u32) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().expect("temp file creation should succeed");
        tmp.write_all(content.as_bytes())
            .expect("write should succeed");
        std::fs::set_permissions(tmp.path(), Permissions::from_mode(mode))
            .expect("set_permissions should succeed");
        tmp
    }

    #[test]
    fn test_reads_ibm_credentials_from_file() {
        let tmp = write_temp_file_with_mode(IBM_JSON, 0o400);
        let path = tmp.path().to_str().expect("path should be valid UTF-8");

        let creds = CredentialFile::from_path(path).expect("from_path should succeed");

        assert_eq!(creds.access_token, "Bearer eyJhbGci...");
        assert_eq!(
            creds.s3_access_key_id.as_deref(),
            Some("abc123")
        );
        assert_eq!(creds.resource_type, "ibm-quantum-system");
        assert_eq!(
            creds.token_expires_at.as_deref(),
            Some("2026-05-20T16:30:00Z")
        );
    }

    #[test]
    fn test_ibm_validate_required_fields() {
        // IBM JSON missing `endpoint` field
        let json_missing_endpoint = r#"{
            "version": "1",
            "resource_name": "test_heron",
            "resource_type": "ibm-quantum-system",
            "access_token": "Bearer eyJhbGci...",
            "token_expires_at": "2026-05-20T16:30:00Z",
            "s3_endpoint": "https://s3.example.com",
            "s3_bucket": "my-bucket",
            "s3_region": "us-east",
            "s3_access_key_id": "abc123",
            "s3_secret_access_key": "xyz789"
        }"#;
        let tmp = write_temp_file_with_mode(json_missing_endpoint, 0o400);
        let path = tmp.path().to_str().expect("path should be valid UTF-8");

        let creds = CredentialFile::from_path(path).expect("from_path should succeed");
        let result = creds.ibm_credentials();

        assert!(result.is_err());
        if let Err(CredentialFileError::MissingField { field, .. }) = result {
            assert_eq!(field, "endpoint");
        } else {
            panic!("expected MissingField error");
        }
    }

    #[test]
    fn test_reads_pasqal_credentials_from_file() {
        let tmp = write_temp_file_with_mode(PASQAL_JSON, 0o400);
        let path = tmp.path().to_str().expect("path should be valid UTF-8");

        let creds = CredentialFile::from_path(path).expect("from_path should succeed");
        let pasqal = creds
            .pasqal_credentials()
            .expect("pasqal_credentials should succeed");

        assert_eq!(pasqal.access_token, "<pasqal-auth0-token>");
        assert!(pasqal.token_expires_at.is_none());
    }

    #[test]
    fn test_pasqal_missing_token_errors() {
        let json_empty_token = r#"{
            "version": "1",
            "resource_name": "FRESNEL",
            "resource_type": "pasqal-cloud",
            "access_token": "",
            "token_expires_at": null
        }"#;
        let tmp = write_temp_file_with_mode(json_empty_token, 0o400);
        let path = tmp.path().to_str().expect("path should be valid UTF-8");

        let creds = CredentialFile::from_path(path).expect("from_path should succeed");
        let result = creds.pasqal_credentials();

        assert!(result.is_err());
        if let Err(CredentialFileError::MissingField { field, .. }) = result {
            assert_eq!(field, "access_token");
        } else {
            panic!("expected MissingField error");
        }
    }

    #[test]
    fn test_rejects_wrong_permissions() {
        let tmp = write_temp_file_with_mode(IBM_JSON, 0o644);
        let path = tmp.path().to_str().expect("path should be valid UTF-8");

        let result = CredentialFile::from_path(path);

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(CredentialFileError::InsecurePermissions { .. })
        ));
    }

    #[test]
    fn test_rejects_unknown_version() {
        let json_v2 = r#"{
            "version": "2",
            "resource_name": "test_heron",
            "resource_type": "ibm-quantum-system",
            "access_token": "Bearer token",
            "token_expires_at": null
        }"#;
        let tmp = write_temp_file_with_mode(json_v2, 0o400);
        let path = tmp.path().to_str().expect("path should be valid UTF-8");

        let result = CredentialFile::from_path(path);

        assert!(result.is_err());
        if let Err(CredentialFileError::UnsupportedVersion { got }) = result {
            assert_eq!(got, "2");
        } else {
            panic!("expected UnsupportedVersion error");
        }
    }

    #[test]
    fn test_returns_none_when_env_var_not_set() {
        // Use a resource name that certainly has no env var set.
        let result = CredentialFile::from_env("NONEXISTENT_RESOURCE_XYZ");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_returns_error_on_missing_file() {
        let result = CredentialFile::from_path("/nonexistent/path.json");
        assert!(result.is_err());
        assert!(matches!(result, Err(CredentialFileError::Io { .. })));
    }
}
