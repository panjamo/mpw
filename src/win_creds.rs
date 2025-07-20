// win_creds.rs - Windows Credential Manager implementation
// This module provides functions to store and retrieve credentials
// using the Windows Credential Manager API directly.

use std::error::Error;
use std::fmt;
use wincredentials::{self, credential};

#[derive(Debug)]
pub enum WinCredError {
    StorageError(String),
    RetrievalError(String),
    NotFound,
    EmptyCredentials,
}

impl fmt::Display for WinCredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WinCredError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            WinCredError::RetrievalError(msg) => write!(f, "Retrieval error: {}", msg),
            WinCredError::NotFound => write!(f, "Credentials not found"),
            WinCredError::EmptyCredentials => write!(f, "Credentials are empty"),
        }
    }
}

impl Error for WinCredError {}

pub struct MpwCredentials {
    service_name: String,
}

impl Default for MpwCredentials {
    fn default() -> Self {
        Self::new("mpw-master-password-manager")
    }
}

impl MpwCredentials {
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }

    pub fn store_username(&self, username: &str) -> Result<(), WinCredError> {
        self.store_credential("username", username)
    }

    pub fn store_password(&self, password: &str) -> Result<(), WinCredError> {
        self.store_credential("password", password)
    }

    pub fn store_credentials(&self, username: &str, password: &str) -> Result<(), WinCredError> {
        self.store_username(username)?;
        self.store_password(password)?;
        Ok(())
    }

    pub fn get_username(&self) -> Result<String, WinCredError> {
        self.get_credential("username")
    }

    pub fn get_password(&self) -> Result<String, WinCredError> {
        self.get_credential("password")
    }

    pub fn get_credentials(&self) -> Result<(String, String), WinCredError> {
        let username = self.get_username()?;
        let password = self.get_password()?;
        
        if username.is_empty() || password.is_empty() {
            return Err(WinCredError::EmptyCredentials);
        }
        
        Ok((username, password))
    }

    pub fn delete_credentials(&self) -> Result<(), WinCredError> {
        let _ = wincredentials::delete_credential(&self.get_target_name("username"));
        let _ = wincredentials::delete_credential(&self.get_target_name("password"));
        Ok(())
    }

    pub fn clear_credentials(&self) -> Result<(), WinCredError> {
        // Instead of deleting, we store empty values
        let _ = self.store_username("");
        let _ = self.store_password("");
        Ok(())
    }

    fn store_credential(&self, credential_type: &str, value: &str) -> Result<(), WinCredError> {
        let target_name = self.get_target_name(credential_type);
        
        let cred = credential::Credential {
            target_name: target_name.clone(),
            comment: format!("MPW {} credential", credential_type),
            username: format!("mpw-{}", credential_type),
            secret: value.to_string(),
            persistence: credential::CredentialPersistence::LocalMachine,
        };
        
        wincredentials::write_credential(&target_name, cred)
            .map_err(|e| WinCredError::StorageError(e.to_string()))
    }

    fn get_credential(&self, credential_type: &str) -> Result<String, WinCredError> {
        let target_name = self.get_target_name(credential_type);
        
        match wincredentials::read_credential(&target_name) {
            Ok(cred) => {
                // Secret is already a String in this API
                Ok(cred.secret)
            },
            Err(_) => Err(WinCredError::NotFound),
        }
    }

    fn get_target_name(&self, credential_type: &str) -> String {
        format!("{}:{}", self.service_name, credential_type)
    }
    
    pub fn verify_storage(&self, username: &str, password: &str) -> Result<bool, WinCredError> {
        // First store the credentials
        self.store_credentials(username, password)?;
        
        // Then try to read them back
        match self.get_credentials() {
            Ok((stored_user, stored_pass)) => {
                Ok(stored_user == username && stored_pass == password)
            },
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_store_and_retrieve() {
        let test_service = "mpw-test-service";
        let creds = MpwCredentials::new(test_service);
        
        // Clean up from previous tests
        let _ = creds.delete_credentials();
        
        // Store credentials
        let username = "test_user";
        let password = "test_password";
        creds.store_credentials(username, password).unwrap();
        
        // Retrieve credentials
        let (retrieved_user, retrieved_pass) = creds.get_credentials().unwrap();
        assert_eq!(retrieved_user, username);
        assert_eq!(retrieved_pass, password);
        
        // Clean up
        creds.delete_credentials().unwrap();
    }
}