<?php

declare(strict_types=1);

namespace App;

use App\Models\Label;
use App\Models\Project;
use App\Models\Task;
use App\Models\User;
use VersaORM\VersaORM;

/**
 * ModelManager: fábrica simple de modelos por petición.
 */
class ModelManager
{
    public function __construct(private VersaORM $orm) {}

    public function project(): Project
    {
        return new Project(Project::tableName(), $this->orm);
    }

    public function task(): Task
    {
        return new Task(Task::tableName(), $this->orm);
    }

    public function user(): User
    {
        return new User(User::tableName(), $this->orm);
    }

    public function label(): Label
    {
        return new Label(Label::tableName(), $this->orm);
    }
}
