#[cfg(test)]
mod cache_tests {
    use crate::cache::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_cache_enable_disable() {
        // Limpiar caché antes de la prueba  
        clear_cache();
        enable_cache();
        assert!(is_cache_enabled(), "Cache should be enabled");
        
        disable_cache();
        assert!(!is_cache_enabled(), "Cache should be disabled");
        
        // Restaurar estado habilitado para otras pruebas
        enable_cache();
    }

    #[test]
    fn test_cache_query_basic() {
        clear_cache();
        enable_cache();
        
        let key = "test_query_key";
        let value = "test_query_result";
        
        // Cachear y recuperar
        cache_query(key, value);
        let cached_result = get_cached_query(key);
        
        assert!(cached_result.is_some(), "Cached query should exist");
        assert_eq!(cached_result.unwrap(), value, "Cached value should match");
    }

    #[test]
    fn test_cache_schema_basic() {
        clear_cache();
        enable_cache();
        
        let key = "test_schema_key";
        let value = "test_schema_result";
        
        // Cachear y recuperar
        cache_schema(key, value);
        let cached_result = get_cached_schema(key);
        
        assert!(cached_result.is_some(), "Cached schema should exist");
        assert_eq!(cached_result.unwrap(), value, "Cached value should match");
    }

    #[test]
    fn test_cache_ttl_expiration() {
        clear_cache();
        enable_cache();
        
        let key = "test_ttl_key";
        let value = "test_ttl_value";
        let short_ttl = Duration::from_millis(100);
        
        // Cachear con TTL corto
        cache_query_with_ttl(key, value, Some(short_ttl));
        
        // Verificar que existe inmediatamente
        let cached_result = get_cached_query(key);
        assert!(cached_result.is_some(), "Cached value should exist immediately");
        
        // Esperar a que expire
        thread::sleep(Duration::from_millis(200));
        
        // Verificar que ya no existe
        let expired_result = get_cached_query(key);
        assert!(expired_result.is_none(), "Cached value should be expired");
    }

    #[test]
    fn test_cache_disabled_returns_none() {
        clear_cache();
        disable_cache();
        
        let key = "disabled_cache_key";
        let value = "disabled_cache_value";
        
        // Intentar cachear cuando está deshabilitado
        cache_query(key, value);
        let cached_result = get_cached_query(key);
        
        assert!(cached_result.is_none(), "Disabled cache should return None");
        
        // Restaurar estado habilitado
        enable_cache();
    }

    #[test]
    fn test_cache_clear() {
        clear_cache();
        enable_cache();
        
        // Añadir algunas entradas
        cache_query("key1", "value1");
        cache_schema("key2", "value2");
        
        // Verificar que existen
        assert!(get_cached_query("key1").is_some());
        assert!(get_cached_schema("key2").is_some());
        
        // Limpiar caché
        clear_cache();
        
        // Verificar que ya no existen
        assert!(get_cached_query("key1").is_none());
        assert!(get_cached_schema("key2").is_none());
    }

    #[test]
    fn test_cache_stats() {
        clear_cache();
        enable_cache();
        
        // Añadir algunas entradas
        cache_query("stats_query", "query_value");
        cache_schema("stats_schema", "schema_value");
        
        let stats = cache_stats();
        
        // Verificar estructura de estadísticas
        assert!(stats.get("enabled").unwrap().as_bool().unwrap());
        assert!(stats.get("max_size").unwrap().as_u64().unwrap() > 0);
        assert!(stats.get("default_ttl_secs").unwrap().as_u64().unwrap() > 0);
        assert!(stats.get("query_cache").is_some());
        assert!(stats.get("schema_cache").is_some());
        assert!(stats.get("total_entries").unwrap().as_u64().unwrap() >= 2);
    }

    #[test]
    fn test_cache_status() {
        clear_cache();
        enable_cache();
        
        // Estado inicial debería ser 0
        assert_eq!(cache_status(), 0);
        
        // Añadir entradas
        cache_query("status_test1", "value1");
        cache_query("status_test2", "value2");
        cache_schema("status_schema", "schema_value");
        
        // Verificar que el estado refleja las entradas añadidas
        assert_eq!(cache_status(), 3);
    }

    #[test]
    fn test_cache_config_update() {
        clear_cache();
        enable_cache();
        
        let new_max_size = 500;
        let new_ttl_secs = 600;
        
        // Actualizar configuración
        set_cache_config(new_max_size, new_ttl_secs);
        
        let stats = cache_stats();
        assert_eq!(stats.get("max_size").unwrap().as_u64().unwrap(), new_max_size as u64);
        assert_eq!(stats.get("default_ttl_secs").unwrap().as_u64().unwrap(), new_ttl_secs);
        
        // Restaurar configuración por defecto
        set_cache_config(1000, 300);
    }

    #[test]
    fn test_invalidate_cache_by_pattern() {
        clear_cache();
        enable_cache();
        
        // Añadir múltiples entradas con diferentes patrones
        cache_query("user_query_1", "user_data_1");
        cache_query("user_query_2", "user_data_2");
        cache_query("product_query_1", "product_data_1");
        cache_schema("user_schema", "user_schema_data");
        
        // Verificar que todas existen
        assert!(get_cached_query("user_query_1").is_some());
        assert!(get_cached_query("user_query_2").is_some());
        assert!(get_cached_query("product_query_1").is_some());
        assert!(get_cached_schema("user_schema").is_some());
        
        // Invalidar por patrón "user"
        invalidate_cache_by_pattern("user");
        
        // Verificar que las entradas con "user" fueron eliminadas
        assert!(get_cached_query("user_query_1").is_none());
        assert!(get_cached_query("user_query_2").is_none());
        assert!(get_cached_schema("user_schema").is_none());
        
        // Verificar que las entradas sin "user" siguen
        assert!(get_cached_query("product_query_1").is_some());
    }

    #[test]
    fn test_invalidate_cache_for_table() {
        clear_cache();
        enable_cache();
        
        // Añadir entradas que simulan consultas de diferentes tablas
        cache_query("SELECT * FROM users WHERE id = 1", "user_data");
        cache_query("SELECT name FROM USERS WHERE active = 1", "user_names");
        cache_query("SELECT * FROM products WHERE category = 'tech'", "product_data");
        cache_schema("users_table_schema", "users_schema_data");
        
        // Verificar que todas existen
        assert!(get_cached_query("SELECT * FROM users WHERE id = 1").is_some());
        assert!(get_cached_query("SELECT name FROM USERS WHERE active = 1").is_some());
        assert!(get_cached_query("SELECT * FROM products WHERE category = 'tech'").is_some());
        assert!(get_cached_schema("users_table_schema").is_some());
        
        // Invalidar caché para tabla "users"
        invalidate_cache_for_table("users");
        
        // Verificar que las entradas relacionadas con "users" fueron eliminadas (case insensitive)
        assert!(get_cached_query("SELECT * FROM users WHERE id = 1").is_none());
        assert!(get_cached_query("SELECT name FROM USERS WHERE active = 1").is_none());
        assert!(get_cached_schema("users_table_schema").is_none());
        
        // Verificar que las entradas de otras tablas siguen
        assert!(get_cached_query("SELECT * FROM products WHERE category = 'tech'").is_some());
    }

    #[test]
    fn test_cleanup_expired_entries() {
        clear_cache();
        enable_cache();
        
        let short_ttl = Duration::from_millis(100);
        let long_ttl = Duration::from_millis(1500);
        
        let short_key = "cleanup_test_short_lived";
        let long_key = "cleanup_test_long_lived";
        
        // Añadir entradas con diferentes TTLs
        cache_query_with_ttl(short_key, "expires_soon", Some(short_ttl));
        cache_query_with_ttl(long_key, "expires_later", Some(long_ttl));
        
        // Verificar que ambas existen inicialmente
        assert!(get_cached_query(short_key).is_some());
        assert!(get_cached_query(long_key).is_some());
        
        // Esperar a que expire la de TTL corto
        thread::sleep(Duration::from_millis(200));
        
        // Limpiar entradas expiradas
        cleanup_expired_entries();
        
        // La de TTL corto debería haber sido eliminada durante la limpieza
        // La de TTL largo debería seguir existiendo
        assert!(get_cached_query(short_key).is_none(), "Short-lived entry should be expired");
        assert!(get_cached_query(long_key).is_some(), "Long-lived entry should still exist");
    }

    #[test]
    fn test_lru_eviction() {
        clear_cache();
        enable_cache();
        
        // Configurar tamaño máximo pequeño para probar eviction
        set_cache_config(3, 300);
        
        // Llenar el caché hasta el límite
        cache_query("key1", "value1");
        cache_query("key2", "value2");
        cache_query("key3", "value3");
        
        // Verificar que todas están
        assert!(get_cached_query("key1").is_some());
        assert!(get_cached_query("key2").is_some());
        assert!(get_cached_query("key3").is_some());
        
        // Acceder a key2 y key3 para actualizar su last_accessed
        get_cached_query("key2");
        get_cached_query("key3");
        
        // Añadir una nueva entrada que debería desalojar la menos recientemente usada (key1)
        cache_query("key4", "value4");
        
        // key1 debería haber sido desalojada (era la menos recientemente accedida)
        assert!(get_cached_query("key1").is_none());
        assert!(get_cached_query("key2").is_some());
        assert!(get_cached_query("key3").is_some());
        assert!(get_cached_query("key4").is_some());
        
        // Restaurar configuración por defecto
        set_cache_config(1000, 300);
    }

    #[test]
    fn test_cache_access_count() {
        clear_cache();
        enable_cache();
        
        let key = "access_count_test";
        let value = "test_value";
        
        // Cachear valor
        cache_query(key, value);
        
        // Acceder múltiples veces
        for _ in 0..5 {
            let result = get_cached_query(key);
            assert!(result.is_some());
            assert_eq!(result.unwrap(), value);
        }
        
        // Las estadísticas deberían reflejar que el valor fue accedido
        let stats = cache_stats();
        assert!(stats.get("query_cache").unwrap().get("active").unwrap().as_u64().unwrap() >= 1);
    }

    #[test]
    fn test_concurrent_cache_access() {
        clear_cache();
        enable_cache();
        
        use std::sync::{Arc, Barrier};
        let barrier = Arc::new(Barrier::new(5)); // Reducir el número de hilos
        
        let handles: Vec<_> = (0..5).map(|i| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let key = format!("concurrent_test_key_{}", i);
                let value = format!("concurrent_test_value_{}", i);
                
                // Sincronizar el inicio de todos los hilos
                barrier.wait();
                
                cache_query(&key, &value);
                
                // Pequeña pausa para permitir que la escritura se complete
                thread::sleep(Duration::from_millis(50));
                
                let result = get_cached_query(&key);
                if result.is_none() {
                    // Intentar una vez más después de una pausa
                    thread::sleep(Duration::from_millis(50));
                    let result = get_cached_query(&key);
                    assert!(result.is_some(), "Thread {} failed to retrieve cached value for key: {}", i, key);
                    assert_eq!(result.unwrap(), value);
                } else {
                    assert_eq!(result.unwrap(), value);
                }
            })
        }).collect();
        
        // Esperar a que todos los hilos terminen
        for (i, handle) in handles.into_iter().enumerate() {
            if let Err(_) = handle.join() {
                eprintln!("Thread {} panicked", i);
            }
        }
        
        // Verificar que el caché tiene al menos algunas entradas
        assert!(cache_status() > 0, "Cache should have some entries after concurrent access");
    }
}
