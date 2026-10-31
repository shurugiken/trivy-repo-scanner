"""Exercise task arguments with stub cmdlets; never register a real task."""
import json
from pathlib import Path
import shutil
import subprocess
import pytest


@pytest.mark.parametrize('whatif', [True, False])
def test_task_registration_is_reviewable(tmp_path, whatif):
    shell = shutil.which('pwsh') or shutil.which('powershell')
    assert shell, 'PowerShell is needed for task registration tests'
    script = Path(__file__).resolve().parents[1] / 'register-task.ps1'
    harness = tmp_path / 'task-test.ps1'
    harness.write_text('''param([string]$Target, [string]$DryRun)
$ErrorActionPreference = 'Stop'
$global:registered = $false
function Get-ScheduledTask { param($TaskName, $ErrorAction) return $null }
function New-ScheduledTaskAction {
    param($Execute, $Argument, $WorkingDirectory)
    if ($Execute -ne 'python') { throw 'wrong executable' }
    if ($Argument -notlike '*"--repos" "fixture repos.json"*') { throw 'quoting lost' }
    if ($Argument -notlike '*"--receipt" "verified.json"*') { throw 'receipt lost' }
    return 'action'
}
function New-ScheduledTaskTrigger {
    param([switch]$Weekly, $DaysOfWeek, $At)
    if (-not $Weekly -or $DaysOfWeek -ne 'Sunday') { throw 'wrong schedule' }
    return 'trigger'
}
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) return 'principal' }
function New-ScheduledTaskSettingsSet {
    param([switch]$StartWhenAvailable, $MultipleInstances, $ExecutionTimeLimit)
    if ($MultipleInstances -ne 'IgnoreNew') { throw 'overlap allowed' }
    return 'settings'
}
function Register-ScheduledTask {
    param($TaskName, $Action, $Trigger, $Principal, $Settings)
    $global:registered = $true
}
& $Target -Python python -Repos 'fixture repos.json' -Executable trivy -Receipt verified.json -Out out -UserId 'local-user' -WhatIf:($DryRun -eq 'yes')
@{ registered = $global:registered } | ConvertTo-Json -Compress
''', encoding='utf-8')
    result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-File', str(harness),
                             str(script), 'yes' if whatif else 'no'], capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    record = json.loads(result.stdout.strip().splitlines()[-1])
    assert record['registered'] is not whatif
