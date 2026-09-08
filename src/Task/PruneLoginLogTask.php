<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Task;

use SilverStripe\Dev\BuildTask;
use SilverStripe\ORM\DB;
use SilverStripe\PolyExecution\PolyOutput;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use XD\OIDCProvider\Model\OAuthLoginLog;

/**
 * Deletes SSO login-log entries older than the retention window
 * (OAuthLoginLog.retention_days, default 365; 0 disables pruning).
 *
 * Schedule it (cron / scheduled task) to keep the audit table from growing
 * unbounded — e.g. daily: sake tasks:oidc-prune-login-log
 */
class PruneLoginLogTask extends BuildTask
{
    protected static string $commandName = 'oidc-prune-login-log';

    protected static string $description = 'Delete SSO login-log entries older than OAuthLoginLog.retention_days.';

    protected string $title = 'OIDC: prune SSO login log';

    protected function execute(InputInterface $input, PolyOutput $output): int
    {
        $days = (int) OAuthLoginLog::config()->get('retention_days');
        if ($days <= 0) {
            $output->writeln('<info>retention_days is 0 — retention disabled, nothing pruned.</info>');
            return Command::SUCCESS;
        }

        $cutoff = date('Y-m-d H:i:s', strtotime("-{$days} days"));
        $table = (string) OAuthLoginLog::config()->get('table_name');

        DB::prepared_query('DELETE FROM "' . $table . '" WHERE "Created" < ?', [$cutoff]);
        $deleted = DB::affected_rows();

        $output->writeln("<info>Pruned {$deleted} SSO login-log entries older than {$days} days (before {$cutoff}).</info>");

        return Command::SUCCESS;
    }
}
