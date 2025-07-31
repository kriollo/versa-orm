use crate::connection::ConnectionManager;
use serde_json::Value;
use std::collections::HashMap;

#[allow(dead_code)]
pub struct Model {
    pub table: String,
    pub primary_key: String,
    pub attributes: HashMap<String, Value>,
    pub connection: ConnectionManager,
}

impl Model {
    #[allow(dead_code)]
    pub fn new(table: &str, primary_key: &str, connection: ConnectionManager) -> Self {
        Self {
            table: table.to_string(),
            primary_key: primary_key.to_string(),
            attributes: HashMap::new(),
            connection,
        }
    }

    // Load data from database to model
    #[allow(dead_code)]
    pub async fn load(&mut self, id: &Value) -> Result<(), String> {
        let query = format!(
            "SELECT * FROM {} WHERE {} = ?",
            self.table, self.primary_key
        );
        if let Ok(rows) = self.connection.execute_raw(&query, vec![id.clone()]).await {
            if let Some(row) = rows.first() {
                self.attributes = row.clone();
                Ok(())
            } else {
                Err("No records found".to_string())
            }
        } else {
            Err("Failed to load data".to_string())
        }
    }

    // Save model data to the database
    #[allow(dead_code)]
    pub async fn save(&self) -> Result<(), String> {
        if self.attributes.is_empty() {
            return Err("No data to save".to_string());
        }
        // Implement the save logic
        // This should handle both insertions and updates
        Ok(())
    }

    // Convert model to JSON
    #[allow(dead_code)]
    pub fn to_json(&self) -> Value {
        serde_json::json!(self.attributes)
    }
}

// Define relationship types
#[allow(dead_code)]
pub enum Relation {
    HasOne,
    HasMany,
    BelongsTo,
    BelongsToMany,
}

// Example association (for simplicity)
#[allow(dead_code)]
pub struct Association {
    pub relation: Relation,
    pub related_table: String,
    pub foreign_key: String,
    pub local_key: String,
}

#[allow(dead_code)]
impl Association {
    pub fn new(
        relation: Relation,
        related_table: &str,
        foreign_key: &str,
        local_key: &str,
    ) -> Self {
        Self {
            relation,
            related_table: related_table.to_string(),
            foreign_key: foreign_key.to_string(),
            local_key: local_key.to_string(),
        }
    }
}
