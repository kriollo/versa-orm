use crate::connection::{ConnectionManager, DatabasePool};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ColumnInfo {
    pub name: String,
    pub data_type: String,
    pub is_nullable: bool,
    pub default_value: Option<String>,
    pub is_primary_key: bool,
    pub is_auto_increment: bool,
    pub character_maximum_length: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TableInfo {
    pub name: String,
    pub columns: Vec<ColumnInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IndexInfo {
    pub name: String,
    pub table_name: String,
    pub column_name: String,
    pub is_unique: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ForeignKeyInfo {
    pub name: String,
    pub table_name: String,
    pub column_name: String,
    pub referenced_table: String,
    pub referenced_column: String,
}

pub struct SchemaInspector<'a> {
    connection: &'a ConnectionManager,
}

impl<'a> SchemaInspector<'a> {
    pub fn new(connection: &'a ConnectionManager) -> Self {
        Self { connection }
    }

    pub async fn get_tables(&self) -> Result<Vec<String>, sqlx::Error> {
        let query = match self.connection.get_driver() {
            "mysql" => "SHOW TABLES",
            "postgres" | "postgresql" => {
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            }
            "sqlite" => "SELECT name FROM sqlite_master WHERE type='table'",
            _ => return Err(sqlx::Error::Configuration("Unsupported database driver".into())),
        };

        let rows = self.connection.execute_raw(query, vec![]).await?;
        let tables = rows
            .into_iter()
            .map(|row| {
                row.values()
                    .next()
                    .unwrap_or(&serde_json::Value::Null)
                    .as_str()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        Ok(tables)
    }

    pub async fn get_columns(&self, table_name: &str) -> Result<Vec<ColumnInfo>, sqlx::Error> {
        let query = match self.connection.get_driver() {
            "mysql" => format!(
                "SELECT 
                    COLUMN_NAME as name,
                    DATA_TYPE as data_type,
                    IS_NULLABLE as is_nullable,
                    COLUMN_DEFAULT as default_value,
                    COLUMN_KEY as column_key,
                    EXTRA as extra,
                    CHARACTER_MAXIMUM_LENGTH as character_maximum_length
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = '{}'",
                table_name
            ),
            "postgres" | "postgresql" => format!(
                "SELECT 
                    column_name as name,
                    data_type,
                    is_nullable,
                    column_default as default_value,
                    character_maximum_length
                FROM information_schema.columns 
                WHERE table_name = '{}'",
                table_name
            ),
            "sqlite" => format!("PRAGMA table_info({})", table_name),
            _ => return Err(sqlx::Error::Configuration("Unsupported database driver".into())),
        };

        let rows = self.connection.execute_raw(&query, vec![]).await?;
        let mut columns = Vec::new();

        for row in rows {
            let column = match self.connection.get_driver() {
                "mysql" => ColumnInfo {
                    name: row.get("name").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                    data_type: row.get("data_type").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                    is_nullable: row.get("is_nullable").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("NO") == "YES",
                    default_value: row.get("default_value").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    is_primary_key: row.get("column_key").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("") == "PRI",
                    is_auto_increment: row.get("extra").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").contains("auto_increment"),
                    character_maximum_length: row.get("character_maximum_length").and_then(|v| v.as_i64()),
                },
                "postgres" | "postgresql" => ColumnInfo {
                    name: row.get("name").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                    data_type: row.get("data_type").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                    is_nullable: row.get("is_nullable").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("NO") == "YES",
                    default_value: row.get("default_value").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    is_primary_key: false, // Would need additional query for PG
                    is_auto_increment: row.get("default_value").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").contains("nextval"),
                    character_maximum_length: row.get("character_maximum_length").and_then(|v| v.as_i64()),
                },
                "sqlite" => ColumnInfo {
                    name: row.get("name").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                    data_type: row.get("type").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                    is_nullable: row.get("notnull").unwrap_or(&serde_json::Value::Null).as_i64().unwrap_or(0) == 0,
                    default_value: row.get("dflt_value").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    is_primary_key: row.get("pk").unwrap_or(&serde_json::Value::Null).as_i64().unwrap_or(0) == 1,
                    is_auto_increment: false, // SQLite handles this differently
                    character_maximum_length: None,
                },
                _ => continue,
            };
            columns.push(column);
        }

        Ok(columns)
    }

    pub async fn get_primary_key(&self, table_name: &str) -> Result<Option<String>, sqlx::Error> {
        let columns = self.get_columns(table_name).await?;
        let primary_key = columns
            .into_iter()
            .find(|col| col.is_primary_key)
            .map(|col| col.name);

        Ok(primary_key)
    }

    pub async fn get_indexes(&self, table_name: &str) -> Result<Vec<IndexInfo>, sqlx::Error> {
        let query = match self.connection.get_driver() {
            "mysql" => format!(
                "SELECT 
                    INDEX_NAME as name,
                    TABLE_NAME as table_name,
                    COLUMN_NAME as column_name,
                    NON_UNIQUE = 0 as is_unique
                FROM INFORMATION_SCHEMA.STATISTICS 
                WHERE TABLE_NAME = '{}'",
                table_name
            ),
            "postgres" | "postgresql" => format!(
                "SELECT 
                    indexname as name,
                    tablename as table_name,
                    indexdef
                FROM pg_indexes 
                WHERE tablename = '{}'",
                table_name
            ),
            "sqlite" => format!("PRAGMA index_list({})", table_name),
            _ => return Err(sqlx::Error::Configuration("Unsupported database driver".into())),
        };

        let rows = self.connection.execute_raw(&query, vec![]).await?;
        let mut indexes = Vec::new();

        for row in rows {
            let index = IndexInfo {
                name: row.get("name").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                table_name: table_name.to_string(),
                column_name: row.get("column_name").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                is_unique: row.get("is_unique").unwrap_or(&serde_json::Value::Bool(false)).as_bool().unwrap_or(false),
            };
            indexes.push(index);
        }

        Ok(indexes)
    }

    pub async fn get_foreign_keys(&self, table_name: &str) -> Result<Vec<ForeignKeyInfo>, sqlx::Error> {
        let query = match self.connection.get_driver() {
            "mysql" => format!(
                "SELECT 
                    CONSTRAINT_NAME as name,
                    TABLE_NAME as table_name,
                    COLUMN_NAME as column_name,
                    REFERENCED_TABLE_NAME as referenced_table,
                    REFERENCED_COLUMN_NAME as referenced_column
                FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
                WHERE TABLE_NAME = '{}' AND REFERENCED_TABLE_NAME IS NOT NULL",
                table_name
            ),
            "postgres" | "postgresql" => format!(
                "SELECT 
                    tc.constraint_name as name,
                    tc.table_name,
                    kcu.column_name,
                    ccu.table_name AS referenced_table,
                    ccu.column_name AS referenced_column
                FROM information_schema.table_constraints AS tc 
                JOIN information_schema.key_column_usage AS kcu
                  ON tc.constraint_name = kcu.constraint_name
                JOIN information_schema.constraint_column_usage AS ccu
                  ON ccu.constraint_name = tc.constraint_name
                WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_name = '{}'",
                table_name
            ),
            "sqlite" => format!("PRAGMA foreign_key_list({})", table_name),
            _ => return Err(sqlx::Error::Configuration("Unsupported database driver".into())),
        };

        let rows = self.connection.execute_raw(&query, vec![]).await?;
        let mut foreign_keys = Vec::new();

        for row in rows {
            let fk = ForeignKeyInfo {
                name: row.get("name").unwrap_or(&serde_json::Value::String("".to_string())).as_str().unwrap_or("").to_string(),
                table_name: table_name.to_string(),
                column_name: row.get("column_name").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                referenced_table: row.get("referenced_table").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
                referenced_column: row.get("referenced_column").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("").to_string(),
            };
            foreign_keys.push(fk);
        }

        Ok(foreign_keys)
    }
}
