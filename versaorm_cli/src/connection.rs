use serde::{Deserialize, Deserializer, Serialize};
use sqlx::{Column, Executor, MySql, Pool, Postgres, Row, Sqlite};
use std::collections::HashMap;

// Importar tipos para DECIMAL
use rust_decimal::Decimal;
use bigdecimal::BigDecimal;

fn deserialize_port<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let s: serde_json::Value = Deserialize::deserialize(deserializer)?;
    match s {
        serde_json::Value::Number(n) => {
            if let Some(num) = n.as_u64() {
                Ok(num as u16)
            } else {
                Err(serde::de::Error::custom("Invalid port number"))
            }
        }
        serde_json::Value::String(s) => {
            s.parse::<u16>().map_err(serde::de::Error::custom)
        }
        _ => Err(serde::de::Error::custom("Port must be a number or string"))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub driver: String,
    pub host: String,
    #[serde(deserialize_with = "deserialize_port")]
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
        Self { config, pool: None }
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

                // Configurar el pool con timeouts más altos para queries complejas
                let pool_options = sqlx::mysql::MySqlPoolOptions::new()
                    .max_connections(5)
                    .acquire_timeout(std::time::Duration::from_secs(60))
                    .idle_timeout(std::time::Duration::from_secs(600))
                    .max_lifetime(std::time::Duration::from_secs(1800));

                let pool = pool_options.connect(&url).await?;

                DatabasePool::MySql(pool)
            }
            "postgres" | "postgresql" | "pgsql" => {
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
            _ => {
                return Err(sqlx::Error::Configuration(
                    "Unsupported database driver".into(),
                ))
            }
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

    pub async fn execute_unprepared(&self, query: &str) -> Result<u64, sqlx::Error> {
        match self.pool.as_ref() {
            Some(DatabasePool::MySql(pool)) => {
                let result = pool.execute(query).await?;
                Ok(result.rows_affected())
            }
            Some(DatabasePool::Postgres(pool)) => {
                let result = pool.execute(query).await?;
                Ok(result.rows_affected())
            }
            Some(DatabasePool::Sqlite(pool)) => {
                let result = pool.execute(query).await?;
                Ok(result.rows_affected())
            }
            None => Err(sqlx::Error::Configuration(
                "Not connected to database".into(),
            )),
        }
    }

    pub async fn execute_raw(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>, sqlx::Error> {
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
            None => Err(sqlx::Error::Configuration(
                "Not connected to database".into(),
            )),
        }
    }

    pub async fn execute_write(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<u64, sqlx::Error> {
        match self.pool.as_ref() {
            Some(DatabasePool::MySql(pool)) => {
                let mut query_builder = sqlx::query(query);
                for param in params {
                    query_builder = bind_value_mysql(query_builder, param);
                }
                let result = query_builder.execute(pool).await?;
                Ok(result.rows_affected())
            }
            Some(DatabasePool::Postgres(pool)) => {
                let mut query_builder = sqlx::query(query);
                for param in params {
                    query_builder = bind_value_postgres(query_builder, param);
                }
                let result = query_builder.execute(pool).await?;
                Ok(result.rows_affected())
            }
            Some(DatabasePool::Sqlite(pool)) => {
                let mut query_builder = sqlx::query(query);
                for param in params {
                    query_builder = bind_value_sqlite(query_builder, param);
                }
                let result = query_builder.execute(pool).await?;
                Ok(result.rows_affected())
            }
            None => Err(sqlx::Error::Configuration(
                "Not connected to database".into(),
            )),
        }
    }

    // Función específica para ejecutar INSERT con RETURNING en PostgreSQL
    pub async fn execute_insert_with_returning(
        &self,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, sqlx::Error> {
        match self.pool.as_ref() {
            Some(DatabasePool::Postgres(pool)) => {
                // Para PostgreSQL, agregar RETURNING id si no existe
                let final_query = if query.trim().to_uppercase().starts_with("INSERT")
                    && !query.to_uppercase().contains("RETURNING") {
                    format!("{} RETURNING id", query)
                } else {
                    query.to_string()
                };

                let mut query_builder = sqlx::query(&final_query);
                for param in params {
                    query_builder = bind_value_postgres(query_builder, param);
                }

                // Ejecutar y obtener el resultado
                let result = query_builder.fetch_one(pool).await?;

                // Debug: Log el resultado completo
                crate::log_debug_msg(&format!("PostgreSQL RETURNING result columns: {:?}",
                    result.columns().iter().map(|c| c.name()).collect::<Vec<_>>()));

                // Extraer el ID retornado
                let id_value = postgres_value_to_json(&result, "id");
                crate::log_debug_msg(&format!("Extracted ID value: {:?}", id_value));

                Ok(serde_json::json!({
                    "id": id_value,
                    "rows_affected": 1
                }))
            }
            Some(DatabasePool::MySql(pool)) => {
                // Para MySQL, usar execute normal y last_insert_id
                let mut query_builder = sqlx::query(query);
                for param in params {
                    query_builder = bind_value_mysql(query_builder, param);
                }
                let result = query_builder.execute(pool).await?;

                Ok(serde_json::json!({
                    "id": result.last_insert_id(),
                    "rows_affected": result.rows_affected()
                }))
            }
            Some(DatabasePool::Sqlite(pool)) => {
                // Para SQLite, usar execute normal y last_insert_rowid
                let mut query_builder = sqlx::query(query);
                for param in params {
                    query_builder = bind_value_sqlite(query_builder, param);
                }
                let result = query_builder.execute(pool).await?;

                Ok(serde_json::json!({
                    "id": result.last_insert_rowid(),
                    "rows_affected": result.rows_affected()
                }))
            }
            None => Err(sqlx::Error::Configuration(
                "Not connected to database".into(),
            )),
        }
    }
}

// Helper functions para binding de parámetros
fn bind_value_mysql(
    query: sqlx::query::Query<'_, MySql, sqlx::mysql::MySqlArguments>,
    value: serde_json::Value,
) -> sqlx::query::Query<'_, MySql, sqlx::mysql::MySqlArguments> {
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

fn bind_value_postgres(
    query: sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments>,
    value: serde_json::Value,
) -> sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments> {
    match value {
        serde_json::Value::String(s) => {
            // Verificar si es un timestamp válido para PostgreSQL
            if is_timestamp_string(&s) {
                // Convertir timestamp string a tipo PostgreSQL compatible
                if let Ok(datetime) = chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S") {
                    query.bind(datetime)
                } else {
                    // Si no se puede parsear como timestamp, bind como string
                    query.bind(s)
                }
            } else {
                query.bind(s)
            }
        },
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
        serde_json::Value::Null => {
            // Para PostgreSQL, bind null como Option<String>::None que es más compatible
            query.bind(Option::<i32>::None)
        },
        _ => query.bind(value.to_string()),
    }
}

// Helper function para detectar si un string es un timestamp
fn is_timestamp_string(s: &str) -> bool {
    // Detectar formato YYYY-MM-DD HH:MM:SS o similar
    let timestamp_regex = regex::Regex::new(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").unwrap();
    timestamp_regex.is_match(s)
}

fn bind_value_sqlite<'a>(
    query: sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>>,
    value: serde_json::Value,
) -> sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>> {
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
fn convert_mysql_rows_to_json(
    rows: Vec<sqlx::mysql::MySqlRow>,
) -> Vec<HashMap<String, serde_json::Value>> {
    rows.into_iter()
        .map(|row| {
            let mut map = HashMap::new();
            for column in row.columns() {
                let column_name = column.name().to_string();
                let value = mysql_value_to_json(&row, column_name.as_str());
                map.insert(column_name, value);
            }
            map
        })
        .collect()
}

fn convert_postgres_rows_to_json(
    rows: Vec<sqlx::postgres::PgRow>,
) -> Vec<HashMap<String, serde_json::Value>> {
    rows.into_iter()
        .map(|row| {
            let mut map = HashMap::new();
            for column in row.columns() {
                let column_name = column.name().to_string();
                let value = postgres_value_to_json(&row, column_name.as_str());
                map.insert(column_name, value);
            }
            map
        })
        .collect()
}

fn convert_sqlite_rows_to_json(
    rows: Vec<sqlx::sqlite::SqliteRow>,
) -> Vec<HashMap<String, serde_json::Value>> {
    rows.into_iter()
        .map(|row| {
            let mut map = HashMap::new();
            for column in row.columns() {
                let column_name = column.name().to_string();
                let value = sqlite_value_to_json(&row, column_name.as_str());
                map.insert(column_name, value);
            }
            map
        })
        .collect()
}

fn mysql_value_to_json(row: &sqlx::mysql::MySqlRow, column_name: &str) -> serde_json::Value {
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    use sqlx::Column;
    use sqlx::Row;

    // DEBUG MODE: Mostrar información detallada sobre el tipo de columna
    if std::env::var("VERSAORM_DEBUG").is_ok() {
        let column_info = row
            .columns()
            .iter()
            .find(|col| col.name() == column_name)
            .map(|col| format!("Column '{}': type_info = {:?}", col.name(), col.type_info()))
            .unwrap_or_else(|| format!("Column '{}': not found", column_name));

        // Use unified logging system
        crate::log_debug_msg(&format!("Column info: {}", column_info));

        // Use unified logging system for debugging type extraction
        crate::log_debug_msg(&format!(
            "Attempting to extract '{}' as various types:",
            column_name
        ));

        if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
            crate::log_debug_msg(&format!("  as String: {:?}", val));
        } else {
            crate::log_debug_msg("  as String: FAILED");
        }

        if let Ok(val) = row.try_get::<Option<Vec<u8>>, _>(column_name) {
            crate::log_debug_msg(&format!("  as Vec<u8>: {:?}", val));
            // Si es Vec<u8>, intentar convertir a string para ver el contenido
            if let Some(bytes) = val {
                if let Ok(string_val) = String::from_utf8(bytes.clone()) {
                    crate::log_debug_msg(&format!("    Vec<u8> as UTF-8 string: {:?}", string_val));
                } else {
                    crate::log_debug_msg("    Vec<u8> cannot be converted to UTF-8");
                }
            }
        } else {
            crate::log_debug_msg("  as Vec<u8>: FAILED");
        }

        if let Ok(val) = row.try_get::<Option<NaiveDateTime>, _>(column_name) {
            crate::log_debug_msg(&format!("  as NaiveDateTime: {:?}", val));
        } else {
            crate::log_debug_msg("  as NaiveDateTime: FAILED");
        }

        if let Ok(val) = row.try_get::<Option<i64>, _>(column_name) {
            crate::log_debug_msg(&format!("  as i64: {:?}", val));
        } else {
            crate::log_debug_msg("  as i64: FAILED");
        }

        if let Ok(val) = row.try_get::<Option<f64>, _>(column_name) {
            crate::log_debug_msg(&format!("  as f64: {:?}", val));
        } else {
            crate::log_debug_msg("  as f64: FAILED");
        }

        // Intentar tipos time crate
        if let Ok(val) = row.try_get::<Option<time::PrimitiveDateTime>, _>(column_name) {
            crate::log_debug_msg(&format!("  as time::PrimitiveDateTime: {:?}", val));
        } else {
            crate::log_debug_msg("  as time::PrimitiveDateTime: FAILED");
        }

        if let Ok(val) = row.try_get::<Option<time::OffsetDateTime>, _>(column_name) {
            crate::log_debug_msg(&format!("  as time::OffsetDateTime: {:?}", val));
        } else {
            crate::log_debug_msg("  as time::OffsetDateTime: FAILED");
        }

        crate::log_debug_msg("---");
    }

    // Manejo específico para tipos TIMESTAMP de MySQL
    // Identificar el tipo de columna para manejo específico
    if let Some(column) = row.columns().iter().find(|col| col.name() == column_name) {
        let type_info = column.type_info();

        // Debug: Log del tipo detectado
        if std::env::var("VERSAORM_DEBUG").is_ok() {
            crate::log_debug_msg(&format!("Processing type: {:?}", type_info));
        }

        // Verificar si es un tipo TIMESTAMP de MySQL
        let type_name = format!("{:?}", type_info);
        if type_name.contains("Timestamp") {
            // Para tipos TIMESTAMP, intentar diferentes aproximaciones

            // Opción 1: Intentar con tipos time crate que sqlx podría usar internamente
            if let Ok(val) = row.try_get::<Option<time::PrimitiveDateTime>, _>(column_name) {
                if std::env::var("VERSAORM_DEBUG").is_ok() {
                    crate::log_debug_msg(&format!(
                        "Successfully extracted TIMESTAMP as time::PrimitiveDateTime: {:?}",
                        val
                    ));
                }
                return match val {
                    Some(dt) => {
                        // Convertir time::PrimitiveDateTime a string
                        let formatted = format!(
                            "{}-{:02}-{:02} {:02}:{:02}:{:02}",
                            dt.year(),
                            dt.month() as u8,
                            dt.day(),
                            dt.hour(),
                            dt.minute(),
                            dt.second()
                        );
                        serde_json::Value::String(formatted)
                    }
                    None => serde_json::Value::Null,
                };
            }

            // Opción 2: Intentar con time::OffsetDateTime
            if let Ok(val) = row.try_get::<Option<time::OffsetDateTime>, _>(column_name) {
                if std::env::var("VERSAORM_DEBUG").is_ok() {
                    crate::log_debug_msg(&format!(
                        "Successfully extracted TIMESTAMP as time::OffsetDateTime: {:?}",
                        val
                    ));
                }
                return match val {
                    Some(dt) => {
                        // Convertir time::OffsetDateTime a string
                        let formatted = format!(
                            "{}-{:02}-{:02} {:02}:{:02}:{:02}",
                            dt.year(),
                            dt.month() as u8,
                            dt.day(),
                            dt.hour(),
                            dt.minute(),
                            dt.second()
                        );
                        serde_json::Value::String(formatted)
                    }
                    None => serde_json::Value::Null,
                };
            }

            if std::env::var("VERSAORM_DEBUG").is_ok() {
                crate::log_debug_msg("Failed to extract TIMESTAMP with time crate types");
            }
        }
    }

    // Lógica original de conversión de tipos

    // Primero intentar tipos DECIMAL específicos
    if let Ok(val) = row.try_get::<Option<Decimal>, _>(column_name) {
        return match val {
            Some(v) => {
                let f_val = v.to_string().parse::<f64>().unwrap_or(0.0);
                serde_json::Number::from_f64(f_val)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::String(v.to_string()))
            },
            None => serde_json::Value::Null,
        };
    }

    if let Ok(val) = row.try_get::<Option<BigDecimal>, _>(column_name) {
        return match val {
            Some(v) => {
                let f_val = v.to_string().parse::<f64>().unwrap_or(0.0);
                serde_json::Number::from_f64(f_val)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::String(v.to_string()))
            },
            None => serde_json::Value::Null,
        };
    }

    // Luego intentar tipos numéricos básicos
    if let Ok(val) = row.try_get::<Option<i64>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::Number(serde_json::Number::from(v)),
            None => serde_json::Value::Null,
        };
    }

    if let Ok(val) = row.try_get::<Option<f64>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Number::from_f64(v)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            None => serde_json::Value::Null,
        };
    }

    // Intentar obtener tipos DECIMAL como String y luego convertir a número
    if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
        return match val {
            Some(v) => {
                // Intentar parsear como número si parece ser un decimal
                if let Ok(f_val) = v.parse::<f64>() {
                    serde_json::Number::from_f64(f_val)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::String(v))
                } else {
                    serde_json::Value::String(v)
                }
            },
            None => serde_json::Value::Null,
        };
    }

    // Manejar tipos de fecha/hora chrono (fallback)
    if let Ok(val) = row.try_get::<Option<NaiveDateTime>, _>(column_name) {
        return match val {
            Some(v) => {
                let formatted = v.format("%Y-%m-%d %H:%M:%S").to_string();
                serde_json::Value::String(formatted)
            }
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

    if let Ok(val) = row.try_get::<Option<bool>, _>(column_name) {
        return match val {
            Some(v) => serde_json::Value::Bool(v),
            None => serde_json::Value::Null,
        };
    }

    serde_json::Value::Null
}

fn postgres_value_to_json(row: &sqlx::postgres::PgRow, column_name: &str) -> serde_json::Value {
    use sqlx::Row;

    println!("DEBUG: postgres_value_to_json - trying to extract column '{}'", column_name);

    // Try i32 first (for SERIAL/INTEGER columns)
    if let Ok(val) = row.try_get::<Option<i32>, _>(column_name) {
        println!("DEBUG: Successfully extracted as i32: {:?}", val);
        return match val {
            Some(v) => serde_json::Value::Number(serde_json::Number::from(v)),
            None => serde_json::Value::Null,
        };
    }

    // Try i64 (for BIGSERIAL/BIGINT columns)
    if let Ok(val) = row.try_get::<Option<i64>, _>(column_name) {
        println!("DEBUG: Successfully extracted as i64: {:?}", val);
        return match val {
            Some(v) => serde_json::Value::Number(serde_json::Number::from(v)),
            None => serde_json::Value::Null,
        };
    }

    if let Ok(val) = row.try_get::<Option<f64>, _>(column_name) {
        println!("DEBUG: Successfully extracted as f64: {:?}", val);
        return match val {
            Some(v) => serde_json::Number::from_f64(v)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            None => serde_json::Value::Null,
        };
    }

    if let Ok(val) = row.try_get::<Option<bool>, _>(column_name) {
        println!("DEBUG: Successfully extracted as bool: {:?}", val);
        return match val {
            Some(v) => serde_json::Value::Bool(v),
            None => serde_json::Value::Null,
        };
    }

    if let Ok(val) = row.try_get::<Option<String>, _>(column_name) {
        println!("DEBUG: Successfully extracted as String: {:?}", val);
        return match val {
            Some(v) => serde_json::Value::String(v),
            None => serde_json::Value::Null,
        };
    }

    println!("DEBUG: Failed to extract column '{}' as any known type", column_name);
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
            Some(v) => serde_json::Number::from_f64(v)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
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
