<?php

declare(strict_types=1);

namespace Controllers;

use App\Models\User;
use Exception;

class UserController
{
    public static function handle(string $action, ?int $id): void
    {
        switch ($action) {
            case 'users':
                $users = models()->user()->all();
                render('users/index', ['users' => $users]);
                break;
            case 'user_create':
                if ($_POST !== []) {
                    try {
                        $user = models()->user()->createOne($_POST);
                        flash('success', 'Usuario creado exitosamente');
                        redirect('?action=users');
                    } catch (Exception $e) {
                        flash('error', 'Error al crear usuario: ' . $e->getMessage());
                    }
                }
                render('users/create');
                break;
            case 'user_edit':
                if ($id === null || $id === 0) {
                    flash('error', 'ID de usuario requerido');
                    redirect('?action=users');
                }
                $user = models()->user()->find($id);
                if (!$user instanceof User) {
                    flash('error', 'Usuario no encontrado');
                    redirect('?action=users');
                }
                if ($_POST !== []) {
                    try {
                        $user->fill($_POST);
                        $user->store();
                        flash('success', 'Usuario actualizado exitosamente');
                        redirect('?action=users');
                    } catch (Exception $e) {
                        flash('error', 'Error al actualizar usuario: ' . $e->getMessage());
                    }
                }
                render('users/edit', ['user' => $user]);
                break;
            case 'user_delete':
                if ($id === null || $id === 0) {
                    flash('error', 'ID de usuario requerido');
                    redirect('?action=users');
                }
                $user = models()->user()->find($id);
                if ($user instanceof User) {
                    $user->trash();
                    flash('success', 'Usuario eliminado exitosamente');
                } else {
                    flash('error', 'Usuario no encontrado');
                }
                redirect('?action=users');
                break;
        }
    }
}
