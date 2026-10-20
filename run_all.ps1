param([string]$Chainsaw = "D:\lab\chainsaw", [string]$Data = "D:\lab\data")
$repo = $PSScriptRoot
$exe  = Join-Path $Chainsaw "chainsaw.exe"
if (-not (Test-Path $exe)) { Write-Error "chainsaw.exe not found at $exe"; exit 1 }
$maps = @("sigma-event-logs-all", "sigma-event-logs-all-FIXED")
$tests = [ordered]@{}
foreach ($t in "T1070","T1136","T1059") {
  $tests[$t] = @(
    "$repo\rules\ai_generated\${t}_v1_run1.yml",
    "$repo\rules\ai_generated\${t}_v1_run2.yml",
    "$repo\rules\ai_generated\${t}_v1_run3.yml",
    "$repo\rules\corrected\${t}_v2.yml",
    "$repo\rules\sigmahq_baseline\baseline_$t")
}
function Get-Count([string]$s) { $m = [regex]::Match($s, "Detections found on (\d+) documents"); if ($m.Success) { [int]$m.Groups[1].Value } else { $null } }
$rows = @()
Push-Location $Chainsaw
foreach ($tech in $tests.Keys) {
  foreach ($rule in $tests[$tech]) {
    if (-not (Test-Path $rule)) { Write-Warning "missing: $rule"; continue }
    $name = Split-Path $rule -Leaf
    $lint = & $exe --no-banner lint $rule --kind sigma 2>&1 | Out-String
    $loaded = if ($lint -match "Validated (\d+) detection rules out of (\d+)") { "$($Matches[1])/$($Matches[2])" } else { "error" }
    foreach ($map in $maps) {
      $mp  = Join-Path $Chainsaw "mappings\$map.yml"
      $atk = & $exe --no-banner hunt (Join-Path $Data "attack\$tech") -s $rule --mapping $mp 2>&1 | Out-String
      $ben = & $exe --no-banner hunt (Join-Path $Data "benign") -s $rule --mapping $mp 2>&1 | Out-String
      $r = [pscustomobject]@{ technique=$tech; rule=$name; mapping=$map; rules_loaded=$loaded; attack_hits=(Get-Count $atk); benign_hits=(Get-Count $ben) }
      $rows += $r
      "{0,-6} {1,-34} {2,-28} loaded {3,-6} attack {4,-4} benign {5}" -f $r.technique,$r.rule,$r.mapping,$r.rules_loaded,$r.attack_hits,$r.benign_hits
    }
  }
}
Pop-Location
$out = Join-Path $repo ("results\rerun_{0}.csv" -f (Get-Date -Format "yyyy-MM-dd"))
$rows | Export-Csv $out -NoTypeInformation -Encoding UTF8
"Saved: $out"
