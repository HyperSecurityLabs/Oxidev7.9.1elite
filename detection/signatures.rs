use std::collections::HashMap;

pub struct SignatureDatabase {
    signatures: HashMap<String, VulnSignature>,
}

#[derive(Clone, Debug)]
pub struct VulnSignature {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub pattern: String,
    pub description: String,
    pub remediation: String,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            signatures: HashMap::new(),
        };
        
        db.load_default_signatures();
        db
    }

    fn load_default_signatures(&mut self) {
        let sigs = vec![
            VulnSignature {
                id: "OXIDE-001".to_string(),
                name: "WordPress Detected".to_string(),
                severity: "Info".to_string(),
                pattern: r"\bwp-content\b|\bwordpress\b".to_string(),
                description: "WordPress installation detected".to_string(),
                remediation: "Ensure WordPress is kept updated".to_string(),
            },
            VulnSignature {
                id: "OXIDE-002".to_string(),
                name: "Drupal CMS Detected".to_string(),
                severity: "Info".to_string(),
                pattern: r"\bdrupal\b|\bDrupal\b".to_string(),
                description: "Drupal CMS detected".to_string(),
                remediation: "Ensure Drupal is kept updated".to_string(),
            },
        ];

        for sig in sigs {
            self.signatures.insert(sig.id.clone(), sig);
        }
    }

    pub fn all(&self) -> &HashMap<String, VulnSignature> {
        &self.signatures
    }

    pub fn add(&mut self, sig: VulnSignature) {
        self.signatures.insert(sig.id.clone(), sig);
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SignatureDatabase {
    fn clone(&self) -> Self {
        Self {
            signatures: self.signatures.clone(),
        }
    }
}
