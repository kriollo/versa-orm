use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use std::fs::{self, File};
use std::path::PathBuf;
use chrono::{Local, Duration, Utc, TimeZone};
use std::io::Write;
use std::sync::Mutex;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref LOG_FILE: Mutex<Option<File>> = Mutex::new(None);
}

fn setup_logging(debug: bool) {
    if !debug {
        return;
    }

    // Usar la misma carpeta de logs que PHP
    let log_dir = PathBuf::from("logs");
    if !log_dir.exists() && fs::create_dir(&log_dir).is_err() {
        return; // Si no se puede crear, no hacer logging
    }

    // Usar el mismo formato de nombre de archivo que PHP (YYYY-MM-DD.log)
    let today = Local::now().format("%Y-%m-%d").to_string();
    let log_path = log_dir.join(format!("{}.log", today));

    if let Ok(file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path) {
        *LOG_FILE.lock().unwrap() = Some(file);
    }

    // Limpiar logs antiguos (mantener solo 7 días)
    cleanup_old_logs(&log_dir);
}

fn cleanup_old_logs(log_dir: &PathBuf) {
    let seven_days_ago = Utc::now() - Duration::days(7);

    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().is_some_and(|ext| ext == "log") {
                if let Some(stem) = path.file_stem() {
                    if let Some(stem_str) = stem.to_str() {
                        // Solo eliminar archivos con formato YYYY-MM-DD
                        if let Ok(date) = chrono::NaiveDate::parse_from_str(stem_str, "%Y-%m-%d") {
                            let datetime = date.and_hms_opt(0, 0, 0).unwrap();
                            if Utc.from_utc_datetime(&datetime) < seven_days_ago {
                                let _ = fs::remove_file(path);
                            }
                        }
                    }
                }
            }
        }
    }
}

macro_rules! log_debug {
    ($($arg:tt)*) => {
        if let Some(ref mut file) = *LOG_FILE.lock().unwrap() {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            writeln!(file, "[{}][DEBUG] {}", timestamp, format!($($arg)*)).unwrap();
        }
    };
}

// Public function for other modules to use
pub fn log_debug_msg(msg: &str) {
    if let Some(ref mut file) = *LOG_FILE.lock().unwrap() {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        writeln!(file, "[{}][DEBUG] {}", timestamp, msg).unwrap();
    }
}

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RelationMetadata {
    pub name: String,
    #[serde(rename = "type")]
    pub relation_type: String, // HasOne, HasMany, BelongsTo, BelongsToMany
    pub related_table: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pivot_table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_pivot_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_pivot_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_key: Option<String>,
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bindings: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<std::collections::HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql_state: Option<String>,
}

#[tokio::main]
async fn main() {
    // Configurar panic hook para capturar panics y convertirlos en errores JSON
    std::panic::set_hook(Box::new(|panic_info| {
        let error_msg = if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else {
            "Unknown panic occurred".to_string()
        };

        let location = if let Some(location) = panic_info.location() {
            format!(" at {}:{}:{}", location.file(), location.line(), location.column())
        } else {
            String::new()
        };

        let response = ErrorResponse {
            status: "error".to_string(),
            error: ErrorDetails {
                code: "PANIC_ERROR".to_string(),
                message: format!("Internal error: {}{}", error_msg, location),
                query: None,
                bindings: None,
                details: None,
                sql_state: None,
            },
        };

        eprintln!("{}", serde_json::to_string(&response).unwrap_or_else(|_|
            r#"{"status":"error","error":{"code":"PANIC_ERROR","message":"Failed to serialize error response"}}"#.to_string()));
    }));

    // Ejecutar la lógica principal directamente
    run_main().await;
}

async fn run_main() {
    let cli = Cli::parse();
    let start_time = Instant::now();

    // Leer entrada: ya sea directa o desde archivo temporal
    let json_input = if cli.json_input.starts_with('@') {
        // Leer desde archivo temporal
        let file_path = &cli.json_input[1..]; // Remover el prefijo '@'
        match std::fs::read_to_string(file_path) {
            Ok(content) => content,
            Err(e) => {
                let response = ErrorResponse {
                    status: "error".to_string(),
                    error: ErrorDetails {
                        code: "FILE_READ_ERROR".to_string(),
                        message: format!("Failed to read temporary file '{}': {}", file_path, e),
                        query: None,
                        bindings: None,
                        details: None,
                        sql_state: None,
                    },
                };
                eprintln!("{}", serde_json::to_string(&response).unwrap());
                return;
            }
        }
    } else {
        // Usar entrada directa
        cli.json_input
    };

    // Intentamos deserializar el JSON de entrada.
    let input_payload: Result<InputPayload, _> = serde_json::from_str(&json_input);

    match input_payload {
        Ok(payload) => {
            // Setup logging
            setup_logging(payload.config.debug);

            // Crear el manager de conexión
            let mut connection_manager = ConnectionManager::new(payload.config);

            // Intentar conectar a la base de datos
            if let Err(e) = connection_manager.connect().await {
                let is_debug = connection_manager.is_debug_mode();
                let message = if is_debug {
                    format!("Database connection failed: {}", e)
                } else {
                    "Database connection failed".to_string()
                };

                let mut details = None;
                if is_debug {
                    let mut debug_info = HashMap::new();
                    debug_info.insert("full_error".to_string(), serde_json::Value::String(e.to_string()));
                    debug_info.insert("config".to_string(), serde_json::to_value(connection_manager.get_config()).unwrap_or(serde_json::Value::Null));
                    details = Some(debug_info);
                }

                let response = ErrorResponse {
                    status: "error".to_string(),
                    error: ErrorDetails {
                        code: "DB_CONN_FAILED".to_string(),
                        message,
                        query: None,
                        bindings: None,
                        details,
                        sql_state: None,
                    },
                };
                eprintln!("{}", serde_json::to_string(&response).unwrap());
                return;
            }

            // Procesar la acción
            let result = match payload.action.as_str() {
                "query" => handle_query_action(&connection_manager, &payload.params).await,
                "schema" => handle_schema_action(&connection_manager, &payload.params).await.map_err(|e| (e, None, None)),
                "raw" => handle_raw_action(&connection_manager, &payload.params).await,
                "cache" => handle_cache_action(&payload.params).map_err(|e| (e, None, None)),
                _ => Err((format!("Unknown action: {}", payload.action), None, None)),
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
                Err((error_msg, query, bindings)) => {
                    let is_debug = connection_manager.is_debug_mode();
                    let message = if is_debug {
                        error_msg.clone()
                    } else {
                        // Mensaje simplificado para producción
                        "Database operation failed".to_string()
                    };

                    let mut details = None;
                    if is_debug {
                        let mut debug_info = HashMap::new();
                        debug_info.insert("full_error".to_string(), serde_json::Value::String(error_msg));
                        debug_info.insert("action".to_string(), serde_json::Value::String(payload.action.clone()));
                        debug_info.insert("execution_time_ms".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(execution_time).unwrap()));
                        details = Some(debug_info);
                    }

                    let response = ErrorResponse {
                        status: "error".to_string(),
                        error: ErrorDetails {
                            code: "EXECUTION_ERROR".to_string(),
                            message,
                            query: if is_debug { query } else { None },
                            bindings: if is_debug { bindings } else { None },
                            details,
                            sql_state: None,
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
                    query: None,
                    bindings: None,
                    details: None,
                    sql_state: None,
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
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let table = params.get("table")
        .and_then(|v| v.as_str())
        .ok_or(("Table name is required".to_string(), None, None))?;

    let method = params.get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("get");

    log_debug!("Received where clauses: {:?}", params.get("where"));

    // Construir la consulta SQL usando QueryBuilder
    let mut query_builder = QueryBuilder::new(table);

    // Manejar datos de inserción si existen
    if method == "insert" || method == "insertGetId" {
        if let Some(insert_data) = params.get("data").and_then(|v| v.as_object()) {
            let mut data_map = HashMap::new();
            for (key, value) in insert_data {
                data_map.insert(key.clone(), value.clone());
            }
            query_builder = query_builder.insert(&data_map);
        }
    }

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
            // Verificar si es una cláusula RAW
            if where_clause.get("type").and_then(|v| v.as_str()) == Some("raw") {
                // Procesar cláusula RAW
                if let (Some(sql), Some(bindings)) = (
                    where_clause.get("sql").and_then(|v| v.as_str()),
                    where_clause.get("bindings").and_then(|v| v.as_array())
                ) {
                    let raw_value = serde_json::json!({
                        "sql": sql,
                        "bindings": bindings
                    });
                    query_builder = query_builder.r#where("", "RAW", raw_value);
                }
            } else {
                // Procesar cláusula normal
                if let (Some(column), Some(operator), Some(value)) = (
                    where_clause.get("column").and_then(|v| v.as_str()),
                    where_clause.get("operator").and_then(|v| v.as_str()),
                    where_clause.get("value")
                ) {
                    let clause_type = where_clause.get("type").and_then(|v| v.as_str()).unwrap_or("and");
                    match clause_type {
                        "or" => query_builder = query_builder.or_where(column, operator, value.clone()),
                        _ => query_builder = query_builder.r#where(column, operator, value.clone()),
                    }
                }
            }
        }
    }

    // Apply joins
    if let Some(joins) = params.get("joins").and_then(|v| v.as_array()) {
        for join_clause in joins {
            if let (Some(table), Some(on), Some(join_type)) = (
                join_clause.get("table").and_then(|v| v.as_str()),
                join_clause.get("on").and_then(|v| v.as_str()),
                join_clause.get("type").and_then(|v| v.as_str())
            ) {
                let parts: Vec<&str> = on.split_whitespace().collect();
                if parts.len() == 3 {
                    let first_col = parts[0];
                    let operator = parts[1];
                    let second_col = parts[2];
                    match join_type {
                        "inner" => query_builder = query_builder.join(table, first_col, operator, second_col),
                        "left" => query_builder = query_builder.left_join(table, first_col, operator, second_col),
                        _ => (),
                    }
                }
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

    // Aplicar group by
    if let Some(group_by) = params.get("groupBy").and_then(|v| v.as_array()) {
        if !group_by.is_empty() {
            let cols: Vec<&str> = group_by.iter()
                .filter_map(|v| v.as_str())
                .collect();
            query_builder = query_builder.group_by(cols);
        }
    }

    // Aplicar having
    if let Some(havings) = params.get("having").and_then(|v| v.as_array()) {
        for having_clause in havings {
            if let (Some(column), Some(operator), Some(value)) = (
                having_clause.get("column").and_then(|v| v.as_str()),
                having_clause.get("operator").and_then(|v| v.as_str()),
                having_clause.get("value")
            ) {
                query_builder = query_builder.having(column, operator, value.clone());
            }
        }
    }

    // Guardar referencia a la tabla antes de mover query_builder
    let table_name = query_builder.table.clone();
    let insert_data_ref = query_builder.insert_data.clone();

    // Construir y ejecutar la consulta
    let (sql, sql_params) = query_builder.build_sql();
    log_debug!("Executing SQL: {}", sql);
    log_debug!("Parameters ({} total):", sql_params.len());
    for (i, param) in sql_params.iter().enumerate() {
        log_debug!("  [{}]: {:?}", i, param);
    }

    match method {
        "get" => {
            let rows = connection.execute_raw(&sql, sql_params.clone()).await
                .map_err(|e| (format!("Query execution failed: {}", e), Some(sql.to_string()), Some(sql_params.clone())))?;
            Ok(serde_json::to_value(rows).unwrap())
        }
        "first" => {
            let rows = connection.execute_raw(&sql, sql_params.clone()).await
                .map_err(|e| (format!("Query execution failed: {}", e), Some(sql.to_string()), Some(sql_params.clone())))?;
            let first_row = rows.into_iter().next();
            Ok(serde_json::to_value(first_row).unwrap())
        }
        "count" => {
            // Convertir SELECT a COUNT usando la misma lógica WHERE
            let count_sql = sql.replacen("SELECT *", "SELECT COUNT(*) as count", 1);
            let count_sql = if count_sql.contains("ORDER BY") {
                // Remover ORDER BY para COUNT ya que no es necesario
                count_sql.split(" ORDER BY").next().unwrap_or(&count_sql).to_string()
            } else {
                count_sql
            };

            let rows = connection.execute_raw(&count_sql, sql_params.clone()).await
                .map_err(|e| (format!("Count query failed: {}", e), Some(count_sql.clone()), Some(sql_params.clone())))?;
            let count = rows.first()
                .and_then(|row| row.get("count"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            Ok(serde_json::Value::Number(serde_json::Number::from(count)))
        }
"insert" => {
            // Construir el SQL de inserción
            if let Some(insert_data) = insert_data_ref {
                let columns: Vec<String> = insert_data.keys().cloned().collect();
                let values: Vec<String> = columns.iter().map(|_| "?".to_string()).collect();
                let insert_sql = format!("INSERT INTO {} ({}) VALUES ({})", table_name, columns.join(", "), values.join(", "));

                // Preparar parámetros de inserción
                let insert_params: Vec<serde_json::Value> = columns.iter()
                    .map(|col| insert_data.get(col).unwrap().clone())
                    .collect();

                // Ejecutar la consulta de inserción
                connection.execute_raw(&insert_sql, insert_params.clone()).await
                    .map_err(|e| (format!("Insert query failed: {}", e), Some(insert_sql.clone()), Some(insert_params.clone())))?;

                Ok(serde_json::json!({"status": "Insert successful", "rows_affected": 1}))
            } else {
                Err(("Insert data is missing".to_string(), None, None))
            }
        }
        "insertGetId" => {
            // Construir el SQL de inserción y obtener el ID generado
            if let Some(insert_data) = insert_data_ref {
                let columns: Vec<String> = insert_data.keys().cloned().collect();
                let values: Vec<String> = columns.iter().map(|_| "?".to_string()).collect();
                let insert_sql = format!("INSERT INTO {} ({}) VALUES ({})", table_name, columns.join(", "), values.join(", "));

                // Preparar parámetros de inserción
                let insert_params: Vec<serde_json::Value> = columns.iter()
                    .map(|col| insert_data.get(col).unwrap().clone())
                    .collect();

                // Ejecutar la consulta de inserción
                connection.execute_raw(&insert_sql, insert_params.clone()).await
                    .map_err(|e| (format!("Insert query failed: {}", e), Some(insert_sql.clone()), Some(insert_params.clone())))?;

                // Obtener el último ID insertado usando MAX(id) como alternativa más confiable
                let last_id_sql = format!("SELECT MAX(id) as id FROM {}", table_name);
                let last_id_rows = connection.execute_raw(&last_id_sql, vec![]).await
                    .map_err(|e| (format!("Failed to get last insert ID: {}", e), Some(last_id_sql.clone()), None))?;

                let last_id = last_id_rows.first()
                    .and_then(|row| row.get("id"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);

                Ok(serde_json::Value::Number(serde_json::Number::from(last_id)))
            } else {
                Err(("Insert data is missing".to_string(), None, None))
            }
        }
        "exists" => {
            let exists_sql = format!("SELECT EXISTS({}) as exists_result", sql);
            let rows = connection.execute_raw(&exists_sql, sql_params.clone()).await
                .map_err(|e| (format!("Exists query failed: {}", e), Some(exists_sql.clone()), Some(sql_params.clone())))?;
            let exists = rows.first()
                .and_then(|row| row.get("exists_result"))
                .map(|v| {
                    // MySQL returns 1 or 0 for EXISTS, convert to boolean
                    if let Some(num) = v.as_i64() {
                        num != 0
                    } else {
                        v.as_bool().unwrap_or_default()
                    }
                })
                .unwrap_or(false);
            Ok(serde_json::Value::Bool(exists))
        }
        "update" => {
            // Construir el SQL de UPDATE
            if let Some(update_data) = params.get("data").and_then(|v| v.as_object()) {
                let mut set_clauses = Vec::new();
                let mut update_params = Vec::new();

                // Construir las cláusulas SET
                for (key, value) in update_data {
                    set_clauses.push(format!("{} = ?", key));
                    update_params.push(value.clone());
                }

                // Extraer la parte WHERE de la consulta SELECT original
                let update_sql = if sql.contains("WHERE") {
                    let where_part = sql.split(" WHERE ").nth(1).unwrap_or("");
                    let where_clause = where_part.split(" ORDER BY").next().unwrap_or(where_part);
                    format!("UPDATE {} SET {} WHERE {}", table, set_clauses.join(", "), where_clause)
                } else {
                    format!("UPDATE {} SET {}", table, set_clauses.join(", "))
                };

                // Combinar parámetros: primero los de SET, luego los de WHERE
                update_params.extend(sql_params.clone());

                let rows_affected = connection.execute_write(&update_sql, update_params.clone()).await
                    .map_err(|e| (format!("Update query failed: {}", e), Some(update_sql.clone()), Some(update_params.clone())))?;

                Ok(serde_json::Value::Number(serde_json::Number::from(rows_affected)))
            } else {
                Err(("Update data is missing".to_string(), None, None))
            }
        }
        "delete" => {
            // Convertir SELECT a DELETE usando la misma lógica WHERE
            let delete_sql = if sql.contains("WHERE") {
                // Extraer la parte WHERE de la consulta SELECT
                let where_part = sql.split(" WHERE ").nth(1).unwrap_or("");
                let where_clause = where_part.split(" ORDER BY").next().unwrap_or(where_part);
                format!("DELETE FROM {} WHERE {}", table, where_clause)
            } else {
                // Si no hay WHERE, eliminar toda la tabla (peligroso, pero es lo que se pide)
                format!("DELETE FROM {}", table)
            };

            let rows_affected = connection.execute_write(&delete_sql, sql_params.clone()).await
                .map_err(|e| (format!("Delete query failed: {}", e), Some(delete_sql.clone()), Some(sql_params.clone())))?;

            Ok(serde_json::Value::Number(serde_json::Number::from(rows_affected)))
        }
        _ => Err((format!("Unsupported method: {}", method), Some(sql.to_string()), Some(sql_params)))
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

/* async fn handle_unprepared_raw_action(
    connection: &ConnectionManager,
    params: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let query = params.get("query")
        .and_then(|v| v.as_str())
        .ok_or(("Query is required for raw action".to_string(), None, None))?;

    connection.execute_unprepared(query).await
        .map(|rows_affected| serde_json::json!({ "rows_affected": rows_affected }))
        .map_err(|e| (format!("Unprepared raw query execution failed: {}", e), Some(query.to_string()), None))
} */

// Handler para consultas SQL raw
async fn handle_raw_action(
    connection: &ConnectionManager,
    params: &HashMap<String, serde_json::Value>,
) -> Result<serde_json::Value, (String, Option<String>, Option<Vec<serde_json::Value>>)> {
    let query = params.get("query")
        .and_then(|v| v.as_str())
        .ok_or(("Query is required for raw action".to_string(), None, None))?;

    let bindings = params.get("bindings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Check if this is a query that needs to be executed without prepared statements
    let query_upper = query.trim().to_uppercase();
    let needs_unprepared = query_upper.starts_with("START TRANSACTION")
        || query_upper.starts_with("COMMIT")
        || query_upper.starts_with("ROLLBACK")
        || query_upper.starts_with("SET FOREIGN_KEY_CHECKS")
        || query_upper.starts_with("TRUNCATE")
        || query_upper.starts_with("DROP TABLE")
        || query_upper.starts_with("CREATE TABLE")
        || query_upper.starts_with("ALTER TABLE");

    if needs_unprepared || bindings.is_empty() {
        // Execute as unprepared query
        connection.execute_unprepared(query).await
            .map(|rows_affected| serde_json::json!({ "rows_affected": rows_affected }))
            .map_err(|e| (format!("Unprepared raw query execution failed: {}", e), Some(query.to_string()), None))
    } else {
        // Execute as prepared query with bindings
        let rows = connection.execute_raw(query, bindings.clone()).await
            .map_err(|e| (format!("Raw query execution failed: {}", e), Some(query.to_string()), Some(bindings.clone())))?;
        Ok(serde_json::to_value(rows).unwrap())
    }
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
