<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use VersaORM\VersaModel;

class TestModel extends VersaModel
{
    protected string $table = 'custom_table';
}
