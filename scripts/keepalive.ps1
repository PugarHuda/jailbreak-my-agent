# Keeps the Jailbreak-My-Agent (npm start) online: restarts it if it crashes or the box
# reboots. The SDK already reconnects the WebSocket on network blips (ws.js
# ping/pong + backoff), so this only supervises the PROCESS.
#
# One WS connection per SDK key is allowed - a second agent process trips a
# "policy violation (duplicate key)" and one drops. So a named mutex enforces a
# single supervisor; don't also run "npm start"/"npm run health" by hand while
# this is up (prove-hire is HTTP-only and is safe to run alongside).
#
# ASCII only: Windows PowerShell 5.1 reads .ps1 as the ANSI codepage, so a
# non-ASCII char (em dash, ellipsis) corrupts parsing. Keep it plain ASCII.
#
# Run now:        powershell -ExecutionPolicy Bypass -File scripts\keepalive.ps1
# Survive reboot: a launcher in the user's Startup folder already runs this at
#   logon (see Jailbreak-My-AgentAgent.cmd). Delete that file to stop auto-starting.

# Continue (not Stop): a transient hiccup must not kill the supervisor itself.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot   # scripts\.. -> repo root
Set-Location $repo

$created = $false
$mutex = New-Object System.Threading.Mutex($true, "Global\Jailbreak-My-AgentAgentKeepalive", [ref]$created)
if (-not $created) {
  Write-Host "keepalive: another supervisor already holds the lock - exiting."
  exit 0
}

# Call operator blocks until the agent exits and needs no console - so this works
# when launched detached/hidden (Start-Process -NoNewWindow would throw there).
Write-Host "keepalive: supervising 'npm start' in $repo (Ctrl+C to stop)"
while ($true) {
  try { & npm.cmd start } catch { Write-Host "keepalive: launch error: $_" }
  Write-Host "keepalive: agent exited at $(Get-Date -Format o), restarting in 5s"
  Start-Sleep -Seconds 5
}
