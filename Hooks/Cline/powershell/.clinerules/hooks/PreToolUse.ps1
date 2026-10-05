# Cline hook shim — Prisma AIRS.
# Cline on Windows discovers <Event>.ps1 in .clinerules/hooks/ (extensionless and
# .cmd shims are BOTH invisible to its win32 discovery — the hook is silently
# inert). Keep this file next to airs-hooks.ps1.
& "$PSScriptRoot\airs-hooks.ps1" -Vendor cline -EventName PreToolUse
exit $LASTEXITCODE
