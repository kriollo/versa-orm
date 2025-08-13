<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Models\UserModel;
use VersaORM\VersaORMException;

use function array_slice;
use function count;
use function defined;

use const DIRECTORY_SEPARATOR;

/**
 * UserController - Ejemplo de controlador con manejo de errores integrado.
 */
class UserController
{
    /**
     * Crear un nuevo usuario.
     */
    public function create(array $requestData): array
    {
        try {
            // Configurar ErrorHandler para esta operación
            ErrorHandler::setDebugMode(true); // En desarrollo

            $response = UserModel::createUser($requestData);

            // Log de la operación
            $this->logControllerAction('create_user', $response['success'], [
                'request_data' => $this->sanitizeLogData($requestData),
                'response'     => $response,
            ]);

            return $response;

        } catch (VersaORMException $e) {
            return $this->handleControllerError($e, 'create_user', $requestData);
        }
    }

    /**
     * Obtener usuario por ID.
     */
    public function show(int $userId): array
    {
        try {
            $user = UserModel::findWithErrorHandling($userId);

            if (!$user) {
                return [
                    'success' => false,
                    'message' => 'User not found',
                    'error'   => [
                        'code'        => 'USER_NOT_FOUND',
                        'suggestions' => ['Verify the user ID is correct', 'Check if the user was deleted'],
                    ],
                ];
            }

            return [
                'success' => true,
                'data'    => $user->toArray(),
            ];

        } catch (VersaORMException $e) {
            return $this->handleControllerError($e, 'show_user', ['user_id' => $userId]);
        }
    }

    /**
     * Actualizar usuario.
     */
    public function update(int $userId, array $requestData): array
    {
        try {
            $user = UserModel::findWithErrorHandling($userId);

            if (!$user) {
                return [
                    'success' => false,
                    'message' => 'User not found',
                    'error'   => ['code' => 'USER_NOT_FOUND'],
                ];
            }

            $response = $user->updateUser($requestData);

            $this->logControllerAction('update_user', $response['success'], [
                'user_id'      => $userId,
                'request_data' => $this->sanitizeLogData($requestData),
            ]);

            return $response;

        } catch (VersaORMException $e) {
            return $this->handleControllerError($e, 'update_user', [
                'user_id'      => $userId,
                'request_data' => $this->sanitizeLogData($requestData),
            ]);
        }
    }

    /**
     * Eliminar usuario.
     */
    public function delete(int $userId): array
    {
        try {
            $user = UserModel::findWithErrorHandling($userId);

            if (!$user) {
                return [
                    'success' => false,
                    'message' => 'User not found',
                    'error'   => ['code' => 'USER_NOT_FOUND'],
                ];
            }

            $result   = $user->safeDelete();
            $response = $user->deleteApiResponse();

            $this->logControllerAction('delete_user', $response['success'], [
                'user_id' => $userId,
            ]);

            return $response;

        } catch (VersaORMException $e) {
            return $this->handleControllerError($e, 'delete_user', ['user_id' => $userId]);
        }
    }

    /**
     * Listar usuarios con paginación.
     */
    public function index(array $filters = [], int $page = 1, int $perPage = 10): array
    {
        try {
            // Construir condiciones de filtro
            $conditions = [];

            if (isset($filters['status'])) {
                $conditions['status'] = $filters['status'];
            }

            if (isset($filters['email'])) {
                $conditions['email'] = $filters['email'];
            }

            $users = UserModel::findAllWithErrorHandling($conditions);

            // Aplicar paginación simple
            $total          = count($users);
            $offset         = ($page - 1) * $perPage;
            $paginatedUsers = array_slice($users, $offset, $perPage);

            return [
                'success'    => true,
                'data'       => array_map(static fn ($user) => $user->toArray(), $paginatedUsers),
                'pagination' => [
                    'current_page' => $page,
                    'per_page'     => $perPage,
                    'total'        => $total,
                    'total_pages'  => ceil($total / $perPage),
                ],
            ];

        } catch (VersaORMException $e) {
            return $this->handleControllerError($e, 'index_users', [
                'filters'  => $filters,
                'page'     => $page,
                'per_page' => $perPage,
            ]);
        }
    }

    /**
     * Activar usuario.
     */
    public function activate(int $userId): array
    {
        try {
            $user = UserModel::findWithErrorHandling($userId);

            if (!$user) {
                return [
                    'success' => false,
                    'message' => 'User not found',
                    'error'   => ['code' => 'USER_NOT_FOUND'],
                ];
            }

            $result = $user->activate();

            return [
                'success' => !$user->hasError(),
                'message' => $user->hasError() ? 'Failed to activate user' : 'User activated successfully',
                'data'    => $user->hasError() ? null : $user->toArray(),
                'error'   => $user->hasError() ? [
                    'message' => $user->getLastErrorMessage(),
                    'code'    => $user->getLastErrorCode(),
                ] : null,
            ];

        } catch (VersaORMException $e) {
            return $this->handleControllerError($e, 'activate_user', ['user_id' => $userId]);
        }
    }

    /**
     * Obtener estadísticas de usuarios.
     */
    public function stats(): array
    {
        try {
            $stats = UserModel::getUserStats();

            return [
                'success' => true,
                'data'    => $stats,
            ];

        } catch (VersaORMException $e) {
            return $this->handleControllerError($e, 'user_stats', []);
        }
    }

    /**
     * Endpoint para debugging - obtener errores recientes.
     */
    public function debugErrors(): array
    {
        if (!$this->isDebugMode()) {
            return [
                'success' => false,
                'message' => 'Debug mode is not enabled',
            ];
        }

        $errors     = ErrorHandler::getErrorLog();
        $userErrors = array_filter($errors, static function ($error) {
            return str_contains($error['context']['model_class'] ?? '', 'UserModel');
        });

        return [
            'success' => true,
            'data'    => [
                'total_errors'  => count($userErrors),
                'recent_errors' => array_slice($userErrors, -10),
                'error_summary' => $this->summarizeErrors($userErrors),
            ],
        ];
    }

    /**
     * Maneja errores del controlador.
     */
    private function handleControllerError(VersaORMException $e, string $action, array $context = []): array
    {
        $errorData = ErrorHandler::handleException($e, array_merge($context, [
            'controller' => static::class,
            'action'     => $action,
            'timestamp'  => date('Y-m-d H:i:s'),
        ]));

        $this->logControllerAction($action, false, [
            'error'   => $errorData,
            'context' => $context,
        ]);

        // En modo debug, incluir información detallada
        if ($this->isDebugMode()) {
            return [
                'success' => false,
                'message' => 'Database operation failed',
                'error'   => [
                    'message'     => $e->getMessage(),
                    'code'        => $e->getErrorCode(),
                    'query'       => $e->getQuery(),
                    'bindings'    => $e->getBindings(),
                    'suggestions' => $errorData['suggestions'],
                ],
                'debug' => [
                    'origin'      => $errorData['origin'],
                    'stack_trace' => $errorData['stack_trace'],
                ],
            ];
        }

        // En producción, información limitada
        return [
            'success' => false,
            'message' => 'An error occurred while processing your request',
            'error'   => [
                'code'      => $e->getErrorCode(),
                'reference' => substr(md5(json_encode($errorData)), 0, 8),
            ],
        ];
    }

    /**
     * Log de acciones del controlador.
     */
    private function logControllerAction(string $action, bool $success, array $context = []): void
    {
        $logData = [
            'controller' => static::class,
            'action'     => $action,
            'success'    => $success,
            'timestamp'  => date('Y-m-d H:i:s'),
            'context'    => $context,
        ];

        // Escribir al log configurado en VersaORM si está disponible
        $logPath = ErrorHandler::getLogPath();

        if ($logPath) {
            $logFile = $logPath . DIRECTORY_SEPARATOR . 'versaorm_controllers_' . date('Y-m-d') . '.log';
            $logLine = json_encode($logData, JSON_UNESCAPED_UNICODE) . PHP_EOL;
            file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
        } else {
            // Fallback al error_log del sistema
            error_log(json_encode($logData));
        }
    }

    /**
     * Sanitiza datos sensibles para logging.
     */
    private function sanitizeLogData(array $data): array
    {
        $sanitized = $data;

        // Remover campos sensibles
        $sensitiveFields = ['password', 'password_confirmation', 'token', 'secret'];

        foreach ($sensitiveFields as $field) {
            if (isset($sanitized[$field])) {
                $sanitized[$field] = '[REDACTED]';
            }
        }

        return $sanitized;
    }

    /**
     * Verifica si estamos en modo debug.
     */
    private function isDebugMode(): bool
    {
        return defined('APP_DEBUG') && APP_DEBUG === true;
    }

    /**
     * Resume errores para estadísticas.
     */
    private function summarizeErrors(array $errors): array
    {
        $summary = [
            'by_error_code' => [],
            'by_operation'  => [],
            'most_recent'   => null,
        ];

        foreach ($errors as $error) {
            $errorCode = $error['error']['error_code'];
            $operation = $error['context']['operation'] ?? 'unknown';

            $summary['by_error_code'][$errorCode] = ($summary['by_error_code'][$errorCode] ?? 0) + 1;
            $summary['by_operation'][$operation]  = ($summary['by_operation'][$operation] ?? 0) + 1;
        }

        if (!empty($errors)) {
            $summary['most_recent'] = end($errors);
        }

        return $summary;
    }
}
