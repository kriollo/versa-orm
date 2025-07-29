use sqlx::{Pool, MySql, Postgres, Sqlite, Row, Column};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub driver: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub charset: Option<String>,
    #[serde(default)]
    pub debug: bool,
}

#[derive(Debug)]
pub enum DatabasePool {
    MySql(Pool<MySql>),
    Postgres(Pool<Postgres>),
    Sqlite(Pool<Sqlite>),
}

pub struct ConnectionManager {
    config: DatabaseConfig,
    pool: Option<DatabasePool>,
}

impl ConnectionManager {
    pub fn new(config: DatabaseConfig) -> Self {
        Self {
            config,
            pool: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), sqlx::Error> {
        let pool = match self.config.driver.as_str() {
            "mysql" => {
                let url = format!(
                    "mysql://{}:{}@{}:{}/{}",
                    self.config.username,
                    self.config.password,
                    self.config.host,
                    self.config.port,
                    self.config.database
                );
                let pool = sqlx::MySqlPool::connect(&url).await?;
                DatabasePool::MySql(pool)
            }
            "postgres" | "postgresql" => {
                let url = format!(
                    "postgres://{}:{}@{}:{}/{}",
                    self.config.username,
                    self.config.password,
                    self.config.host,
                    self.config.port,
                    self.config.database
                );
                let pool = sqlx::PgPool::connect(&url).await?;
                DatabasePool::Postgres(pool)
            }
            "sqlite" => {
                let url = format!("sqlite:{}", self.config.database);
                let pool = sqlx::SqlitePool::connect(&url).await?;
                DatabasePool::Sqlite(pool)
            }
            _ => return Err(sqlx::Error::Configuration("Unsupported database driver".into())),
        };

        self.pool = Some(pool);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_pool(&self) -> Option<&DatabasePool> {
        self.pool.as_ref()
    }

    #[allow(dead_code)]
    pub fn is_connected(&self) -> bool {
        self.pool.is_some()
    }

    pub fn get_driver(&self) -> &str {
        &self.config.driver
    }
    
    pub fn is_debug_mode(&self) -> bool {
        self.config.debug
    }
    
    pub fn get_config(&self) -> &DatabaseConfig {
        &self.config
    }

    pub async fn execute_raw(&self, query: &str, params: Vec<serde_json::Value>) -> Result<Vec<HashMap<String, serde_json::Value>>, sqlx::Error> {
        match self.pool.as_ref() {
            Some(DatabasePool::MySql(pool)) => {
                let mut query_builder = sqlx::query(query);
                for param in params {
                    query_builder = bind_value_mysql(query_builder, param);
                }
                let rows = query_builder.fetch_all(pool).await?;
                Ok(convert_mysql_rows_to_json(rows))
            }
            Some(DatabasePool::Postgres(pool)) => {
                let mut query_builder = sqlx::query(query);
                for param in params {
                    query_builder = bind_value_postgres(query_builder, param);
                }
                let rows = query_builder.fetch_all(pool).await?;
                Ok(convert_postgres_rows_to_json(rows))
            }
            Some(DatabasePool::Sqlite(pool)) => {
                let mut query_builder = sqlx::query(query);
                for param in params {
                    query_builder = bind_value_sqlite(query_builder, param);
                }
                let rows = query_builder.fetch_all(pool).await?;
                Ok(convert_sqlite_rows_to_json(rows))
            }
            None => Err(sqlx::Error::Configuration("Not connected to database".into())),
        }
    }
}

// Helper functions para binding de parámetros
fn bind_value_mysql(query: sqlx::query::Query<'_, MySql, sqlx::mysql::MySqlArguments>, value: serde_json::Value) -> sqlx::query::Query<'_, MySql, sqlx::mysql::MySqlArguments> {
    match value {
        serde_json::Value::String(s) => query.bind(s),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                query.bind(i)
            } else if let Some(f) = n.as_f64() {
                query.bind(f)
            } else {
                query.bind(n.to_string())
            }
        }
        serde_json::Value::Bool(b) => query.bind(b),
        serde_json::Value::Null => query.bind(Option::<String>::None),
        _ => query.bind(value.to_string()),
    }
}

fn bind_value_postgres(query: sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments>, value: serde_json::Value) -> sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments> {
    match value {
        serde_json::Value::String(s) => query.bind(s),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                query.bind(i)
            } else if let Some(f) = n.as_f64() {
                query.bind(f)
            } else {
                query.bind(n.to_string())
            }
        }
        serde_json::Value::Bool(b) => query.bind(b),
        serde_json::Value::Null => query.bind(Option::<String>::None),
        _ => query.bind(value.to_string()),
    }
}

fn bind_value_sqlite<'a>(query: sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>>, value: serde_json::Value) -> sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>> {
    match value {
        serde_json::Value::String(s) => query.bind(s),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                query.bind(i)
            } else if let Some(f) = n.as_f64() {
                query.bind(f)
            } else {
                query.bind(n.to_string())
            }
        }
        serde_json::Value::Bool(b) => query.bind(b),
        serde_json::Value::Null => query.bind(Option::<String>::None),
        _ => query.bind(value.to_string()),
    }
}

// Helper functions para conversión de rows a JSON
fn convert_mysql_rows_to_json(rows: Vec<sqlx::mysql::MySqlRow>) -> Vec<HashMap<String, serde_json::Value>> {
    rows.into_iter().map(|row| {
        let mut map = HashMap::new();
        for column in row.columns() {
            let column_name = column.name().to_string();
            let value = mysql_value_to_json(&row, column_name.as_str());
            map.insert(column_name, value);
        }
        map
    }).collect()
}

fn convert_postgres_rows_to_json(rows: Vec<sqlx::postgres::PgRow>) -> Vec<HashMap<String, serde_json::Value>> {
    rows.into_iter().map(|row| {
        let mut map = HashMap::new();
        for column in row.columns() {
            let column_name = column.name().to_string();
            let value = postgres_value_to_json(&row, column_name.as_str());
            map.insert(column_name, value);
        }
        map
    }).collect()
}

fn convert_sqlite_rows_to_json(rows: Vec<sqlx::sqlite::SqliteRow>) -> Vec<HashMap<String, serde_json::Value>> {
    rows.into_iter().map(|row| {
        let mut map = HashMap::new();
        for column in row.columns() {
            let column_name = column.name().to_string();
            let value = sqlite_value_to_json(&row, column_name.as_str());
            map.insert(column_name, value);
        }
        map
    }).collect()
}

fn mysql_value_to_json(row: &sqlx::mysql::MySqlRow, column_name: &str) -> serde_json::Value {
    use sqlx::Row;
    use chrono::{NaiveDateTime, NaiveDate, NaiveTime};
    use sqlx::Column;
    

    // DEBUG MODE: Mostrar información detallada sobre el tipo de columna
    if std::env::var("VERSAORM_DEBUG").is_ok() {
        let column_info = row.columns().iter()
            .find(|col| col.name() == column_name)
            .map(|col| format!("Column '{}': type_info = {:?}", col.name(), col.type_info()))
            .unwrap_or_else(|| format!("Column '{}': not found", column_name));
        
        // Escribir debug info a archivo temporal
        use std::fs::OpenOptions;
        use std::io::Write;
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("versaorm_debug.log") {
            let _ = writeln!(file, "[DEBUG] {}", column_info);
        }
        
        // Intentar obtener el valor raw de diferentes maneras para debug
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("versaorm_debug.log") {
            
            let _ = writeln!(file, "[DEBUG] Attempting to extract '{}' as various types:", column_name);
            
            if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
                let _ = writeln!(file, "[DEBUG]   as String: {:?}", val);
            } else {
                let _ = writeln!(file, "[DEBUG]   as String: FAILED");
            }
            
            if let Ok(val) = row.try_get::<Option<Vec<u8>>, _>(column_name) {
                let _ = writeln!(file, "[DEBUG]   as Vec<u8>: {:?}", val);
                // Si es Vec<u8>, intentar convertir a string para ver el contenido
                if let Some(bytes) = val {
                    if let Ok(string_val) = String::from_utf8(bytes.clone()) {
                        let _ = writeln!(file, "[DEBUG]     Vec<u8> as UTF-8 string: {:?}", string_val);
                    } else {
                        let _ = writeln!(file, "[DEBUG]     Vec<u8> cannot be converted to UTF-8");
                    }
                }
            } else {
                let _ = writeln!(file, "[DEBUG]   as Vec<u8>: FAILED");
            }
            
            if let Ok(val) = row.try_get::<Option<NaiveDateTime>, _>(column_name) {
                let _ = writeln!(file, "[DEBUG]   as NaiveDateTime: {:?}", val);
            } else {
                let _ = writeln!(file, "[DEBUG]   as NaiveDateTime: FAILED");
            }
            
            if let Ok(val) = row.try_get::<Option<i64>, _>(column_name) {
                let _ = writeln!(file, "[DEBUG]   as i64: {:?}", val);
            } else {
                let _ = writeln!(file, "[DEBUG]   as i64: FAILED");
            }
            
            if let Ok(val) = row.try_get::<Option<f64>, _>(column_name) {
                let _ = writeln!(file, "[DEBUG]   as f64: {:?}", val);
            } else {
                let _ = writeln!(file, "[DEBUG]   as f64: FAILED");
            }
            
            // Intentar tipos time crate
            if let Ok(val) = row.try_get::<Option<time::PrimitiveDateTime>, _>(column_name) {
                let _ = writeln!(file, "[DEBUG]   as time::PrimitiveDateTime: {:?}", val);
            } else {
                let _ = writeln!(file, "[DEBUG]   as time::PrimitiveDateTime: FAILED");
            }
            
            if let Ok(val) = row.try_get::<Option<time::OffsetDateTime>, _>(column_name) {
                let _ = writeln!(file, "[DEBUG]   as time::OffsetDateTime: {:?}", val);
            } else {
                let _ = writeln!(file, "[DEBUG]   as time::OffsetDateTime: FAILED");
            }
            
            let _ = writeln!(file, "[DEBUG] ---");
        }
    }
    
    // Manejo específico para tipos TIMESTAMP de MySQL
    // Identificar el tipo de columna para manejo específico
    if let Some(column) = row.columns().iter().find(|col| col.name() == column_name) {
        let type_info = column.type_info();
        
        // Debug: Log del tipo detectado
        if std::env::var("VERSAORM_DEBUG").is_ok() {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("versaorm_debug.log") {
                let _ = writeln!(file, "[DEBUG] Processing type: {:?}", type_info);
            }
        }
        
        // Verificar si es un tipo TIMESTAMP de MySQL
        let type_name = format!("{:?}", type_info);
        if type_name.contains("Timestamp") {
            // Para tipos TIMESTAMP, intentar diferentes aproximaciones
            
            // Opción 1: Intentar con tipos time crate que sqlx podría usar internamente
            if let Ok(val) = row.try_get::<Option<time::PrimitiveDateTime>, _>(column_name) {
                if std::env::var("VERSAORM_DEBUG").is_ok() {
                    use std::io::Write;
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("versaorm_debug.log") {
                        let _ = writeln!(file, "[DEBUG] Successfully extracted TIMESTAMP as time::PrimitiveDateTime: {:?}", val);
                    }
                }
                return match val {
                    Some(dt) => {
                        // Convertir time::PrimitiveDateTime a string
                        let formatted = format!("{}-{:02}-{:02} {:02}:{:02}:{:02}",
                            dt.year(), dt.month() as u8, dt.day(),
                            dt.hour(), dt.minute(), dt.second());
                        serde_json::Value::String(formatted)
                    },
                    None => serde_json::Value::Null,
                };
            }
            
            // Opción 2: Intentar con time::OffsetDateTime
            if let Ok(val) = row.try_get::<Option<time::OffsetDateTime>, _>(column_name) {
                if std::env::var("VERSAORM_DEBUG").is_ok() {
                    use std::io::Write;
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("versaorm_debug.log") {
                        let _ = writeln!(file, "[DEBUG] Successfully extracted TIMESTAMP as time::OffsetDateTime: {:?}", val);
                    }
                }
                return match val {
                    Some(dt) => {
                        // Convertir time::OffsetDateTime a string
                        let formatted = format!("{}-{:02}-{:02} {:02}:{:02}:{:02}",
                            dt.year(), dt.month() as u8, dt.day(),
                            dt.hour(), dt.minute(), dt.second());
                        serde_json::Value::String(formatted)
                    },
                    None => serde_json::Value::Null,
                };
            }
            
            if std::env::var("VERSAORM_DEBUG").is_ok() {
                use std::io::Write;
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("versaorm_debug.log") {
                    let _ = writeln!(file, "[DEBUG] Failed to extract TIMESTAMP with time crate types");
                }
            }
        }
    }
    
    // Lógica original de conversión de tipos
    
    // Intentar obtener como String (para otros tipos de columnas)
    if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::String(v),
            None => serde_json::Value::Null,
        };
    }
    
    // Manejar tipos de fecha/hora chrono (fallback)
    if let Ok(val) = row.try_get::<Option<NaiveDateTime>, _>(column_name) {
        return match val {
            Some(v) => {
                let formatted = v.format("%Y-%m-%d %H:%M:%S").to_string();
                serde_json::Value::String(formatted)
            },
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<NaiveDate>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::String(v.format("%Y-%m-%d").to_string()),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<NaiveTime>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::String(v.format("%H:%M:%S").to_string()),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<i64>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::Number(serde_json::Number::from(v)),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<f64>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Number::from_f64(v).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<bool>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::Bool(v),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::String(v),
            None => serde_json::Value::Null,
        };
    }
    
    serde_json::Value::Null
}

fn postgres_value_to_json(row: &sqlx::postgres::PgRow, column_name: &str) -> serde_json::Value {
    use sqlx::Row;
    
    if let Ok(val) = row.try_get::<Option<i64>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::Number(serde_json::Number::from(v)),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<f64>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Number::from_f64(v).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<bool>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::Bool(v),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::String(v),
            None => serde_json::Value::Null,
        };
    }
    
    serde_json::Value::Null
}

fn sqlite_value_to_json(row: &sqlx::sqlite::SqliteRow, column_name: &str) -> serde_json::Value {
    use sqlx::Row;
    
    if let Ok(val) = row.try_get::<Option<i64>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::Number(serde_json::Number::from(v)),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<f64>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Number::from_f64(v).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<bool>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::Bool(v),
            None => serde_json::Value::Null,
        };
    }
    
    if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::String(v),
            None => serde_json::Value::Null,
        };
    }
    
    serde_json::Value::Null
}
