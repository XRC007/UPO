# ==============================================================================
# benchmark.ps1  —  Side-by-side timing: UPO (main.py) vs NPOv2.py  (--test-limit 1000)
# Run from the UPO directory:  .\benchmark.ps1
# ==============================================================================

$ErrorActionPreference = "Continue"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $dir

# ── Force UTF-8 so Rich box-drawing chars render correctly ────────────────────
chcp 65001 | Out-Null                                   # console code page → UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$OutputEncoding            = [System.Text.Encoding]::UTF8
$env:PYTHONUTF8            = "1"                        # tell Python to use UTF-8 I/O
$env:PYTHONIOENCODING      = "utf-8"

function Run-Script {
    param(
        [string]$Label,
        [string]$Script,
        [string[]]$ScriptArgs
    )

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  RUNNING: $Label" -ForegroundColor Cyan
    Write-Host "  Command: python $Script $($ScriptArgs -join ' ')" -ForegroundColor DarkCyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Tee output: display live AND capture for parsing
    $outLines = @()
    python $Script @ScriptArgs 2>&1 | ForEach-Object {
        Write-Host $_
        $outLines += $_
    }

    $sw.Stop()
    $wallSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)

    # ── Parse key metrics from captured output ────────────────────────────
    $collected = 0
    $tcpOpen   = 0
    $verified  = 0
    $elapsed   = $wallSec   # fall back to wall clock

    foreach ($line in $outLines) {
        # "Total Raw Proxies: 12,345"  /  "unique proxies"
        if ($line -match "(\d[\d,]+)\s+unique proxies|Total Raw Proxies:\s*([\d,]+)") {
            $raw = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
            $collected = [int]($raw -replace ',','')
        }
        # NPOv2: "TCP Pre-filter: 1,000 → 477 open endpoints."
        # UPO:   "✓ TCP pre-filter: 143,228 → 57,000 (-...)"
        if ($line -match "TCP [Pp]re-filter.*?→\s*([\d,]+)\s+open|TCP [Pp]re-filter[^→]+→\s*([\d,]+)") {
            $raw = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
            $tcpOpen = [int]($raw -replace ',','')
        }
        # "Final alive: 123"  or  "Alive & Exported: 123"
        if ($line -match "Final alive:\s*([\d,]+)|Alive.*Exported:\s*([\d,]+)") {
            $n = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
            $verified = [int]($n -replace ',','')
        }
        # Script's own elapsed line: "Total: 234.5s" / "Total elapsed: 234.5s"
        if ($line -match "Total(?:\s+elapsed)?:\s*([\d.]+)s") {
            $elapsed = [double]$Matches[1]
        }
    }

    return [PSCustomObject]@{
        Label     = $Label
        WallSec   = $wallSec
        Elapsed   = $elapsed
        Collected = $collected
        TCPOpen   = $tcpOpen
        Verified  = $verified
    }
}

# ── Run UPO (baseline) ────────────────────────────────────────────────────────
# UPO is now a package: the entry point is main.py (UPO.py was split into src/UPO/).
$upo = Run-Script -Label "UPO (main.py)" -Script "main.py" `
    -ScriptArgs "--test-limit","1000","--no-crawl4ai","--no-speed-test","--no-stealth","--no-protocol-detect","--no-dns-leak","--no-ban-check"

Start-Sleep -Seconds 5   # let sockets TIME_WAIT drain between runs

# ── Run NPOv2.py (new) ────────────────────────────────────────────────────────
$npo = Run-Script -Label "NPOv2.py (patched)" -Script "NPOv2.py" `
    -ScriptArgs "--test-limit","1000","--no-crawl4ai"

# ── Print comparison table ────────────────────────────────────────────────────
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host "  BENCHMARK RESULTS  --  test-limit 1000" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Green

$metrics = @(
    @{ Metric = "Wall-clock time (s)";    UPO = $upo.WallSec;   NPO = $npo.WallSec   },
    @{ Metric = "Script-reported time";   UPO = $upo.Elapsed;   NPO = $npo.Elapsed   },
    @{ Metric = "Proxies collected";      UPO = $upo.Collected; NPO = $npo.Collected },
    @{ Metric = "TCP open (post-filter)"; UPO = $upo.TCPOpen;   NPO = $npo.TCPOpen   },
    @{ Metric = "Verified alive";         UPO = $upo.Verified;  NPO = $npo.Verified  }
)

# Print table header
Write-Host ("{0,-32} {1,16} {2,16} {3,12}" -f "Metric", "UPO (before)", "NPOv2 (after)", "Change") -ForegroundColor White
Write-Host ("-" * 80) -ForegroundColor DarkGray

foreach ($row in $metrics) {
    $u = $row.UPO
    $n = $row.NPO
    $delta = "n/a"
    if ($u -is [double] -or $u -is [int]) {
        if ([double]$u -gt 0) {
            $pct   = [math]::Round((([double]$n - [double]$u) / [double]$u) * 100, 1)
            $sign  = if ($pct -lt 0) { "" } else { "+" }
            $delta = "$sign$pct%"
        }
    }
    $colour = "Gray"
    if ($delta -ne "n/a") {
        $pctVal = [double]($delta -replace '[+%]','')
        # For time metrics, negative is better (faster); for proxies, positive is better.
        if ($row.Metric -like "*time*") {
            $colour = if ($pctVal -lt 0) { "Green" } else { "Red" }
        } else {
            $colour = if ($pctVal -gt 0) { "Green" } elseif ($pctVal -lt 0) { "Red" } else { "Gray" }
        }
    }
    Write-Host ("{0,-32} {1,16} {2,16} {3,12}" -f $row.Metric, $u, $n, $delta) -ForegroundColor $colour
}

Write-Host ("-" * 80) -ForegroundColor DarkGray

# Speed-up summary
if ($upo.WallSec -gt 0 -and $npo.WallSec -gt 0) {
    $speedup = [math]::Round($upo.WallSec / $npo.WallSec, 2)
    $colour  = if ($speedup -ge 1.0) { "Green" } else { "Yellow" }
    Write-Host ""
    Write-Host ("  Speed-up factor (wall clock): {0}x" -f $speedup) -ForegroundColor $colour
}
Write-Host ("=" * 70) -ForegroundColor Green
