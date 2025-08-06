use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Operaciones JSON específicas por motor de base de datos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonOperation {
    pub column: String,
    pub path: String,
    pub operation_type: JsonOperationType,
    pub value: Option<Value>,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JsonOperationType {
    Extract,          // ->, ->>, #>, #>>
    ExtractText,      // ->>, #>>
    Contains,         // @>, <@
    ContainsKey,      // ?
    ContainsAny,      // ?|
    ContainsAll,      // ?&
    Update,           // JSON_SET, jsonb_set
    Remove,           // JSON_REMOVE, #-
    Insert,           // JSON_INSERT, ||
}

/// Operaciones con arrays (específicas de PostgreSQL principalmente)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArrayOperation {
    pub column: String,
    pub operation_type: ArrayOperationType,
    pub value: Option<Value>,
    pub index: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArrayOperationType {
    Contains,         // @>
    ContainedBy,      // <@
    Overlap,          // &&
    Length,           // array_length
    Append,           // ||
    Prepend,          // ||
    Remove,           // array_remove
    RemoveIndex,      // array_remove
    Position,         // array_position
    ToText,           // array_to_string
}

/// Operaciones de búsqueda de texto completo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullTextOperation {
    pub columns: Vec<String>,
    pub search_term: String,
    pub operation_type: FullTextType,
    pub options: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FullTextType {
    MySQLFullText,         // MATCH() AGAINST()
    MySQLMatch,            // MATCH() AGAINST()
    PostgreSQLTsVector,    // to_tsvector @@ to_tsquery
    PostgreSQLSimilarity,  // similarity() function
    SqliteFts,             // FTS5 MATCH
}

/// Optimizaciones y hints específicos por motor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryHint {
    pub hint_type: HintType,
    pub value: String,
    pub table: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HintType {
    IndexHint,           // USE INDEX, FORCE INDEX
    JoinHint,            // HASH JOIN, NESTED LOOP
    OptimizerHint,       // /*+ HINT */
    LockHint,            // FOR UPDATE, LOCK IN SHARE MODE
}

/// Características específicas de motores de base de datos
#[derive(Debug, Clone, Default)]
pub struct DatabaseSpecificFeatures {
    pub json_operations: Vec<JsonOperation>,
    pub array_operations: Vec<ArrayOperation>,
    pub fulltext_operations: Vec<FullTextOperation>,
    pub query_hints: Vec<QueryHint>,
}

impl DatabaseSpecificFeatures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Valida que el driver esté soportado
    pub fn validate_driver(&self, database_type: &str) -> bool {
        matches!(database_type.to_lowercase().as_str(), "mysql" | "postgresql" | "sqlite")
    }

    /// Verifica si el motor soporta JSON
    pub fn supports_json(&self, database_type: &str) -> bool {
        match database_type.to_lowercase().as_str() {
            "mysql" => true,    // MySQL 5.7+
            "postgresql" => true, // PostgreSQL 9.2+
            "sqlite" => true,   // SQLite 3.38+
            _ => false,
        }
    }

    /// Verifica si el motor soporta CTEs
    pub fn supports_ctes(&self, database_type: &str) -> bool {
        match database_type.to_lowercase().as_str() {
            "mysql" => true,  // MySQL 8.0+
            "postgresql" => true,
            "sqlite" => true, // SQLite 3.8.3+
            _ => false,
        }
    }

    /// Verifica si el motor soporta window functions
    pub fn supports_window_functions(&self, database_type: &str) -> bool {
        match database_type.to_lowercase().as_str() {
            "mysql" => true,    // MySQL 8.0+
            "postgresql" => true, // PostgreSQL
            "sqlite" => true,   // SQLite 3.25+
            _ => false,
        }
    }

    /// Verifica si el motor soporta full-text search
    pub fn supports_full_text_search(&self, database_type: &str) -> bool {
        match database_type.to_lowercase().as_str() {
            "mysql" => true,
            "postgresql" => true,
            "sqlite" => true, // Con FTS5
            _ => false,
        }
    }

    /// Optimiza consulta para el motor específico
    pub fn optimize_query_for_driver(&self, query: &str, database_type: &str) -> String {
        match database_type.to_lowercase().as_str() {
            "mysql" => {
                if query.contains("LIMIT") && !query.contains("ORDER BY") {
                    format!("{} -- Sugerencia: Agregar ORDER BY para resultados consistentes", query)
                } else {
                    query.to_string()
                }
            }
            "postgresql" => query.to_string(),
            "sqlite" => query.to_string(),
            _ => query.to_string(),
        }
    }

    /// Obtiene límites específicos del motor
    pub fn get_driver_limits(&self, database_type: &str) -> serde_json::Value {
        match database_type.to_lowercase().as_str() {
            "mysql" => serde_json::json!({
                "max_query_size": 1048576,
                "max_table_name_length": 64,
                "max_column_name_length": 64,
                "max_index_name_length": 64,
                "max_connections": 100000,
                "max_packet_size": 1073741824
            }),
            "postgresql" => serde_json::json!({
                "max_query_size": 1073741824,
                "max_table_name_length": 63,
                "max_column_name_length": 63,
                "max_index_name_length": 63,
                "max_connections": 8192,
                "max_packet_size": 1073741824
            }),
            "sqlite" => serde_json::json!({
                "max_query_size": 1000000000,
                "max_table_name_length": 1000000000,
                "max_column_name_length": 1000000000,
                "max_index_name_length": 1000000000,
                "max_connections": 1,
                "max_packet_size": 1000000000
            }),
            _ => serde_json::json!({
                "max_query_size": 65536,
                "max_table_name_length": 32,
                "max_column_name_length": 32,
                "max_index_name_length": 32,
                "max_connections": 100,
                "max_packet_size": 1048576
            }),
        }
    }

    /// Construye full-text search específico del motor
    pub fn build_full_text_search(
        &self,
        table: &str,
        columns: &[String],
        search_term: &str,
        database_type: &str,
    ) -> String {
        match database_type.to_lowercase().as_str() {
            "mysql" => {
                format!(
                    "SELECT * FROM {} WHERE MATCH({}) AGAINST('{}' IN BOOLEAN MODE)",
                    table,
                    columns.join(", "),
                    search_term
                )
            }
            "postgresql" => {
                let tsvector_columns: Vec<String> = columns
                    .iter()
                    .map(|col| format!("to_tsvector('english', {})", col))
                    .collect();
                format!(
                    "SELECT * FROM {} WHERE {} @@ plainto_tsquery('english', '{}')",
                    table,
                    tsvector_columns.join(" || ' ' || "),
                    search_term
                )
            }
            "sqlite" => {
                format!(
                    "SELECT * FROM {} WHERE {} MATCH '{}'",
                    table,
                    table, // Asume tabla FTS5
                    search_term
                )
            }
            _ => {
                // Fallback genérico
                let like_conditions: Vec<String> = columns
                    .iter()
                    .map(|col| format!("{} LIKE '%{}%'", col, search_term))
                    .collect();
                format!("SELECT * FROM {} WHERE {}", table, like_conditions.join(" OR "))
            }
        }
    }
}
