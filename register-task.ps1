[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$Python,
    [Parameter(Mandatory = $true)][string]$Repos,
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$Receipt,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$UserId
)
$ErrorActionPreference = 'Stop'
# https://learn.microsoft.com/powershell/module/scheduledtasks/new-scheduledtaskaction
$taskName = 'Local repository security scan'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'Task exists. Review it before making changes.'
}
$scanner = Join-Path $PSScriptRoot 'scanner.py'
$arguments = @($scanner, 'run', '--repos', $Repos, '--executable', $Executable,
               '--receipt', $Receipt, '--out', $Out)
# Refuse characters that would break Windows command-line quoting.
foreach ($item in @($Python) + $arguments) {
    if ($item.Contains('"') -or $item.Contains("`n") -or $item.Contains("`r") -or $item.EndsWith('\')) {
        throw 'Arguments require plain paths without quotes or a trailing backslash.'
    }
}
$quoted = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
$action = New-ScheduledTaskAction -Execute $Python -Argument $quoted -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At '22:00'
if (-not $UserId) { $UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
$principal = New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 6)
if ($PSCmdlet.ShouldProcess($taskName, 'Register weekly local scan')) {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
}
