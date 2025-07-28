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

    pub fn get_pool(&self) -> Option<&DatabasePool> {
        self.pool.as_ref()
    }

    pub fn is_connected(&self) -> bool {
        self.pool.is_some()
    }

    pub fn get_driver(&self) -> &str {
        &self.config.driver
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
fn bind_value_mysql(mut query: sqlx::query::Query<'_, MySql, sqlx::mysql::MySqlArguments>, value: serde_json::Value) -> sqlx::query::Query<'_, MySql, sqlx::mysql::MySqlArguments> {
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

fn bind_value_postgres(mut query: sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments>, value: serde_json::Value) -> sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments> {
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

fn bind_value_sqlite<'a>(mut query: sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>>, value: serde_json::Value) -> sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>> {
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
    
    // Intentamos obtener el valor como diferentes tipos
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
