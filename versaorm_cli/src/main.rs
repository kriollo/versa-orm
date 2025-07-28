use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

// Módulos del ORM
mod connection;
mod query;
mod model;
mod schema;
mod utils;
mod cache;

use connection::{ConnectionManager, DatabaseConfig};
use schema::SchemaInspector;
use query::QueryBuilder;

// Definimos la estructura para los argumentos de la línea de comandos.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// La carga útil (payload) en formato JSON como una cadena.
    #[arg(value_name = "JSON_INPUT")]
    json_input: String,
}

// Estructuras para el JSON de entrada (Input)
#[derive(Serialize, Deserialize, Debug)]
struct InputPayload {
    config: DatabaseConfig,
    action: String,
    params: HashMap<String, serde_json::Value>,
}

// Estructuras para el JSON de salida (Output)
#[derive(Serialize, Debug)]
struct SuccessResponse<T> {
    status: String,
    data: T,
    metadata: ResponseMetadata,
}

#[derive(Serialize, Debug)]
struct ResponseMetadata {
    execution_time_ms: f64,
    item_count: usize,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    status: String,
    error: ErrorDetails,
}

#[derive(Serialize, Debug)]
struct ErrorDetails {
    code: String,
    message: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let start_time = Instant::now();

    // Intentamos deserializar el JSON de entrada.
    let input_payload: Result<InputPayload, _> = serde_json::from_str(&cli.json_input);

    match input_payload {
        Ok(payload) => {
            // Crear el manager de conexión
            let mut connection_manager = ConnectionManager::new(payload.config);
            
            // Intentar conectar a la base de datos
            if let Err(e) = connection_manager.connect().await {
                let response = ErrorResponse {
                    status: "error".to_string(),
                    error: ErrorDetails {
                        code: "DB_CONN_FAILED".to_string(),
                        message: format!("Database connection failed: {}", e),
                    },
                };
                eprintln!("{}", serde_json::to_string(&response).unwrap());
                return;
            }

            // Procesar la acción
            let result = match payload.action.as_str() {
                "query" => handle_query_action(&connection_manager, &payload.params).await,
                "schema" => handle_schema_action(&connection_manager, &payload.params).await,
                "raw" => handle_raw_action(&connection_manager, &payload.params).await,
                "cache" => handle_cache_action(&payload.params),
                _ => Err(format!("Unknown action: {}", payload.action)),
            };

            let execution_time = start_time.elapsed().as_millis() as f64;

            match result {
                Ok(data) => {
                    let item_count = match &data {
                        serde_json::Value::Array(arr) => arr.len(),
                        serde_json::Value::Null => 0,
                        _ => 1,
                    };

                    let response = SuccessResponse {
                        status: "success".to_string(),
                        data,
                        metadata: ResponseMetadata {
                            execution_time_ms: execution_time,
                            item_count,
                        },
                    };
                    println!("{}", serde_json::to_string(&response).unwrap());
                }
                Err(e) => {
                    let response = ErrorResponse {
                        status: "error".to_string(),
                        error: ErrorDetails {
                            code: "EXECUTION_ERROR".to_string(),
                            message: e,
                        },
                    };
                    eprintln!("{}", serde_json::to_string(&response).unwrap());
                }
            }
        }
        Err(e) => {
            let response = ErrorResponse {
                status: "error".to_string(),
                error: ErrorDetails {
                    code: "INVALID_JSON".to_string(),
                    message: format!("Failed to parse JSON input: {}", e),
                },
            };
            eprintln!("{}", serde_json::to_string(&response).unwrap());
        }
    }
}

// Handler para acciones de query
async fn handle_query_action(
    connection: &ConnectionManager,
    params: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let table = params.get("table")
        .and_then(|v| v.as_str())
        .ok_or("Table name is required")?;

    let method = params.get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("get");

    // Construir la consulta SQL usando QueryBuilder
    let mut query_builder = QueryBuilder::new(table);

    // Aplicar selects
    if let Some(selects) = params.get("select").and_then(|v| v.as_array()) {
        if !selects.is_empty() {
            let cols: Vec<&str> = selects.iter()
                .filter_map(|v| v.as_str())
                .collect();
            query_builder = query_builder.select(cols);
        }
    }

    // Aplicar wheres
    if let Some(wheres) = params.get("where").and_then(|v| v.as_array()) {
        for where_clause in wheres {
            if let (Some(column), Some(operator), Some(value)) = (
                where_clause.get("column").and_then(|v| v.as_str()),
                where_clause.get("operator").and_then(|v| v.as_str()),
                where_clause.get("value")
            ) {
                query_builder = query_builder.r#where(column, operator, value.clone());
            }
        }
    }

    // Aplicar order by
    if let Some(order_by) = params.get("orderBy").and_then(|v| v.as_array()) {
        if let Some(order) = order_by.first() {
            if let (Some(column), Some(direction)) = (
                order.get("column").and_then(|v| v.as_str()),
                order.get("direction").and_then(|v| v.as_str())
            ) {
                query_builder = query_builder.order_by(column, direction);
            }
        }
    }

    // Aplicar limit
    if let Some(limit) = params.get("limit").and_then(|v| v.as_i64()) {
        query_builder = query_builder.limit(limit);
    }

    // Aplicar offset
    if let Some(offset) = params.get("offset").and_then(|v| v.as_i64()) {
        query_builder = query_builder.offset(offset);
    }

    // Construir y ejecutar la consulta
    let sql = query_builder.build_sql::<sqlx::MySql>();
    
    match method {
        "get" => {
            let rows = connection.execute_raw(&sql, vec![]).await
                .map_err(|e| format!("Query execution failed: {}", e))?;
            Ok(serde_json::to_value(rows).unwrap())
        }
        "first" => {
            let rows = connection.execute_raw(&sql, vec![]).await
                .map_err(|e| format!("Query execution failed: {}", e))?;
            let first_row = rows.into_iter().next();
            Ok(serde_json::to_value(first_row).unwrap())
        }
        "count" => {
            let count_sql = format!("SELECT COUNT(*) as count FROM {}", table);
            let rows = connection.execute_raw(&count_sql, vec![]).await
                .map_err(|e| format!("Count query failed: {}", e))?;
            let count = rows.first()
                .and_then(|row| row.get("count"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            Ok(serde_json::Value::Number(serde_json::Number::from(count)))
        }
        "exists" => {
            let exists_sql = format!("SELECT EXISTS({}) as exists_result", sql);
            let rows = connection.execute_raw(&exists_sql, vec![]).await
                .map_err(|e| format!("Exists query failed: {}", e))?;
            let exists = rows.first()
                .and_then(|row| row.get("exists_result"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(serde_json::Value::Bool(exists))
        }
        _ => Err(format!("Unsupported method: {}", method))
    }
}

// Handler para acciones de schema
async fn handle_schema_action(
    connection: &ConnectionManager,
    params: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let subject = params.get("subject")
        .and_then(|v| v.as_str())
        .ok_or("Subject is required for schema action")?;

    let inspector = SchemaInspector::new(connection);

    match subject {
        "tables" => {
            let tables = inspector.get_tables().await
                .map_err(|e| format!("Failed to get tables: {}", e))?;
            Ok(serde_json::to_value(tables).unwrap())
        }
        "columns" => {
            let table_name = params.get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Table name is required for columns subject")?;
            let columns = inspector.get_columns(table_name).await
                .map_err(|e| format!("Failed to get columns: {}", e))?;
            Ok(serde_json::to_value(columns).unwrap())
        }
        "primaryKey" => {
            let table_name = params.get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Table name is required for primaryKey subject")?;
            let pk = inspector.get_primary_key(table_name).await
                .map_err(|e| format!("Failed to get primary key: {}", e))?;
            Ok(serde_json::to_value(pk).unwrap())
        }
        "indexes" => {
            let table_name = params.get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Table name is required for indexes subject")?;
            let indexes = inspector.get_indexes(table_name).await
                .map_err(|e| format!("Failed to get indexes: {}", e))?;
            Ok(serde_json::to_value(indexes).unwrap())
        }
        "foreignKeys" => {
            let table_name = params.get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Table name is required for foreignKeys subject")?;
            let fks = inspector.get_foreign_keys(table_name).await
                .map_err(|e| format!("Failed to get foreign keys: {}", e))?;
            Ok(serde_json::to_value(fks).unwrap())
        }
        _ => Err(format!("Unknown schema subject: {}", subject))
    }
}

// Handler para consultas SQL raw
async fn handle_raw_action(
    connection: &ConnectionManager,
    params: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let query = params.get("query")
        .and_then(|v| v.as_str())
        .ok_or("Query is required for raw action")?;

    let bindings = params.get("bindings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let rows = connection.execute_raw(query, bindings).await
        .map_err(|e| format!("Raw query execution failed: {}", e))?;

    Ok(serde_json::to_value(rows).unwrap())
}

// Handler para acciones de cache
fn handle_cache_action(
    params: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let action = params.get("action")
        .and_then(|v| v.as_str())
        .ok_or("Action is required for cache")?;

    match action {
        "enable" => {
            cache::enable_cache();
            Ok(serde_json::Value::String("Cache enabled".to_string()))
        }
        "disable" => {
            cache::disable_cache();
            Ok(serde_json::Value::String("Cache disabled".to_string()))
        }
        "clear" => {
            cache::clear_cache();
            Ok(serde_json::Value::String("Cache cleared".to_string()))
        }
        "status" => {
            let status = cache::cache_status();
            Ok(serde_json::Value::Number(serde_json::Number::from(status)))
        }
        _ => Err(format!("Unknown cache action: {}", action))
    }
}
