<#
.SYNOPSIS
    Vydání nástroje PyControl do katalogu jedním příkazem.

.DESCRIPTION
    Spouští se na počítači vlastníka v klonu repozitáře (ne na serveru).
    Postup: git pull -> kontrola verze -> validate --run-tests -> build (podpis balíčku)
    -> catalog add -> catalog sign -> catalog validate -> potvrzení -> commit -> push.
    Když cokoli selže nebo vydání nepotvrdíte, katalog se vrátí do původního stavu
    a nový balíček se smaže.

.PARAMETER Nastroj
    ID nástroje (sample.hello), název složky v zdroje\ (sample_hello) nebo cesta ke složce.

.PARAMETER Zmeny
    Co je nového (zobrazí se v konzoli serveru). Když chybí, skript se zeptá.

.PARAMETER BezpecnostniPoznamky
    Bezpečnostně významné změny (nová oprávnění, vyšší riziko...). Nepovinné.

.PARAMETER Stahnout
    ID nástroje, jehož vydání se má stáhnout z nabídky (spolu s -Verze).

.PARAMETER Klic
    Soukromý podpisový klíč. Výchozí C:\Klice\pycontrol-release.pem.
    Ve stejné složce musí být i veřejný klíč .pub (pro závěrečnou kontrolu).

.PARAMETER BezPush
    Připraví a zapíše commit jen lokálně, na GitHub nic neodešle.

.EXAMPLE
    .\vydat.ps1 sample.hello -Zmeny "První vydání"

.EXAMPLE
    .\vydat.ps1 -Stahnout sample.hello -Verze 1.0.1
#>
[CmdletBinding(DefaultParameterSetName = 'Vydat')]
param(
    [Parameter(ParameterSetName = 'Vydat', Mandatory = $true, Position = 0)]
    [string]$Nastroj,

    [Parameter(ParameterSetName = 'Vydat')]
    [string]$Zmeny = '',

    [Parameter(ParameterSetName = 'Vydat')]
    [string]$BezpecnostniPoznamky = '',

    [Parameter(ParameterSetName = 'Stahnout', Mandatory = $true)]
    [string]$Stahnout,

    [Parameter(ParameterSetName = 'Stahnout', Mandatory = $true)]
    [string]$Verze,

    [string]$Klic = 'C:\Klice\pycontrol-release.pem',

    [string]$Vydavatel = 'Jan',

    [switch]$BezPush
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$env:PYTHONIOENCODING = 'utf-8'

$Repo    = $PSScriptRoot
$Katalog = Join-Path $Repo 'catalog.json'
$Podpis  = Join-Path $Repo 'catalog.json.sig'
$Balicky = Join-Path $Repo 'balicky'
$Zdroje  = Join-Path $Repo 'zdroje'

# --- pomocné funkce ------------------------------------------------------------------------
function Krok([string]$Text) {
    Write-Host ''
    Write-Host "== $Text" -ForegroundColor Cyan
}

function Konec([string]$Text, [string]$Rada = '') {
    Write-Host ''
    Write-Host "CHYBA: $Text" -ForegroundColor Red
    if ($Rada) { Write-Host "  $Rada" -ForegroundColor Yellow }
    exit 1
}

function Publish {
    # Spustí pycontrol-publish; při chybě vyhodí výjimku (a tím spustí vrácení změn).
    & $script:PublishExe @args
    if ($LASTEXITCODE -ne 0) { throw "pycontrol-publish $($args[0]) $($args[1]) skončil chybou." }
}

function Spust-Git {
    & git -C $script:Repo @args
    if ($LASTEXITCODE -ne 0) { throw "git $($args[0]) skončil chybou." }
}

function Nacti-Json([string]$Cesta) {
    return (Get-Content -LiteralPath $Cesta -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Porovnej-Verze([string]$A, [string]$B) {
    # Vrací -1/0/1, nebo $null, když verze nejde porovnat.
    try { return ([System.Version]$A).CompareTo([System.Version]$B) } catch { return $null }
}

# --- 1. kontrola prostředí ---------------------------------------------------------------
Krok 'Kontrola prostředí'

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Konec 'Git není nainstalovaný nebo není v PATH.' 'Nainstalujte Git for Windows a otevřete nové okno PowerShellu.'
}
$cmd = Get-Command pycontrol-publish -ErrorAction SilentlyContinue
if (-not $cmd) {
    Konec 'Příkaz pycontrol-publish nebyl nalezen.' `
          'Nainstalujte ho: pip install pycontrol-1.2.0-py3-none-any.whl (a otevřete nové okno PowerShellu).'
}
$script:PublishExe = $cmd.Source

# Python, ve kterém je pycontrol-publish nainstalovaný (kvůli pytestu pro --run-tests)
$kandidati = @()
$scriptsDir = Split-Path $cmd.Source -Parent
$kandidati += (Join-Path (Split-Path $scriptsDir -Parent) 'python.exe')
foreach ($n in @('python', 'py')) {
    $c = Get-Command $n -ErrorAction SilentlyContinue
    if ($c) { $kandidati += $c.Source }
}
$ErrorActionPreference = 'Continue'   # tiché zkoušky (PS 5.1 jinak bere stderr jako chybu)
$python = $null
foreach ($k in $kandidati) {
    if (-not (Test-Path -LiteralPath $k)) { continue }
    & $k -c 'import pycontrol' 2>$null
    if ($LASTEXITCODE -eq 0) { $python = $k; break }
}
if ($python) {
    & $python -c 'import pytest' 2>$null
    if ($LASTEXITCODE -ne 0) {
        Konec 'Chybí pytest (potřebný pro testy nástroje).' "Nainstalujte ho: & `"$python`" -m pip install pytest"
    }
} else {
    Write-Host '  Upozornění: nepodařilo se ověřit pytest – pokud testy selžou, nainstalujte: pip install pytest' -ForegroundColor Yellow
}

& git -C $Repo rev-parse --is-inside-work-tree *> $null
$jeRepo = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = 'Stop'
if (-not $jeRepo) { Konec "Složka $Repo není repozitář Gitu." 'Spusťte skript z klonu repozitáře nástrojů.' }

$gitEmail = (& git -C $Repo config user.email)
$gitJmeno = (& git -C $Repo config user.name)
if (-not $gitEmail -or -not $gitJmeno) {
    Konec 'Git nemá nastavené jméno nebo e-mail autora commitů.' `
          'Nastavte: git config --global user.name "Jan Rudolf"; git config --global user.email "vas@email"'
}

if (-not (Test-Path -LiteralPath $Klic)) {
    Konec "Soukromý klíč $Klic neexistuje." 'Zadejte cestu parametrem -Klic, nebo klíč vytvořte: pycontrol-publish keygen --out C:\Klice --name "..."'
}
$KlicPlny = (Resolve-Path -LiteralPath $Klic).Path
if ($KlicPlny.StartsWith($Repo.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    Konec 'Soukromý klíč leží uvnitř repozitáře!' 'Přesuňte ho mimo repozitář (např. do C:\Klice) – nesmí se dostat na GitHub.'
}
$SlozkaKlicu = Split-Path $KlicPlny -Parent
if (-not (Get-ChildItem -LiteralPath $SlozkaKlicu -Filter '*.pub' -ErrorAction SilentlyContinue)) {
    Konec "Ve složce $SlozkaKlicu chybí veřejný klíč .pub." 'Je potřeba pro závěrečnou kontrolu podpisu (vzniká spolu se soukromým klíčem příkazem keygen).'
}
Write-Host "  pycontrol-publish: $($script:PublishExe)"
Write-Host "  klíč:              $KlicPlny"

# --- 2. aktuální stav z GitHubu ----------------------------------------------------------
Krok 'Stažení aktuálního stavu z GitHubu (git pull)'
$zmenene = & git -C $Repo status --porcelain -- catalog.json catalog.json.sig balicky
if ($zmenene) {
    Write-Host ($zmenene -join "`n")
    Konec 'Katalog nebo balíčky mají neuložené změny.' 'Vraťte je (git checkout -- catalog.json ...) nebo je nejdřív zveřejněte.'
}
try { Spust-Git pull --ff-only } catch { Konec 'Stažení z GitHubu selhalo.' 'Zkontrolujte připojení a že v klonu nemáte vlastní commity, které na GitHubu nejsou.' }

# --- 3. příprava konkrétní akce ------------------------------------------------------------
$katalogExistoval = Test-Path -LiteralPath $Katalog
$novyBalicek = $null

if ($PSCmdlet.ParameterSetName -eq 'Vydat') {
    # Najít složku nástroje
    $slozka = $null
    foreach ($k in @("$Zdroje\$Nastroj", "$Zdroje\$($Nastroj -replace '\.', '_')", $Nastroj)) {
        try {
            if (Test-Path -LiteralPath "$k\tool.json") { $slozka = (Resolve-Path -LiteralPath $k).Path; break }
        } catch { }
    }
    if (-not $slozka) { Konec "Nástroj '$Nastroj' nebyl nalezen." "Hledáno v $Zdroje (podle ID i názvu složky)." }

    $manifest = Nacti-Json (Join-Path $slozka 'tool.json')
    $id = $manifest.id; $ver = $manifest.version
    $novyBalicek = Join-Path $Balicky "$id-$ver.pctool"

    if ($katalogExistoval) {
        $komp = @((Nacti-Json $Katalog).components | Where-Object { $_.id -eq $id })
        if ($komp.Count -gt 0) {
            foreach ($v in $komp[0].versions) {
                if ($v.version -eq $ver) {
                    Konec "$id $ver už je vydaný." 'Zvyšte verzi v tool.json (oprava 1.0.1, nová funkce 1.1.0, nekompatibilní změna 2.0.0).'
                }
                $cmp = Porovnej-Verze $ver $v.version
                if ($null -ne $cmp -and $cmp -lt 0) {
                    Konec "Verze $ver je nižší než už vydaná $($v.version)." 'Servery by ji nenabídly jako aktualizaci. Zvyšte verzi v tool.json.'
                }
            }
        }
    }
    if (Test-Path -LiteralPath $novyBalicek) {
        Konec "Balíček $novyBalicek už existuje, ale v katalogu není (zbytek po nedokončeném vydání?)." 'Smažte ho a spusťte vydání znovu.'
    }
    if (-not $Zmeny) { $Zmeny = Read-Host 'Co je nového v této verzi (zobrazí se na serveru)' }
    if (-not $Zmeny) { Konec 'Popis změn je povinný.' 'Zadejte ho parametrem -Zmeny "..."' }

    Write-Host ''
    Write-Host "  Nástroj: $($manifest.name) ($id)"
    Write-Host "  Verze:   $ver"
    Write-Host "  Riziko:  $($manifest.risk)"
    Write-Host "  Složka:  $slozka"
} else {
    $id = $Stahnout; $ver = $Verze
    if (-not $katalogExistoval) { Konec 'Katalog zatím neexistuje – není co stahovat.' }
    Write-Host "  Stažení z nabídky: $id $ver"
}

$podpisExistoval  = Test-Path -LiteralPath $Podpis
$zaloha = Join-Path ([System.IO.Path]::GetTempPath()) ("pycontrol-vydat-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $zaloha | Out-Null
if ($katalogExistoval) { Copy-Item -LiteralPath $Katalog -Destination $zaloha }
if ($podpisExistoval)  { Copy-Item -LiteralPath $Podpis  -Destination $zaloha }

# --- 4. sestavení, katalog, podpis (při chybě se vše vrátí) --------------------------------
$hotovo = $false
Push-Location $Repo
try {
    if ($PSCmdlet.ParameterSetName -eq 'Vydat') {
        Krok 'Kontrola manifestu a testy nástroje'
        Publish validate $slozka --run-tests

        Krok 'Sestavení a podpis balíčku'
        Publish build $slozka --key $KlicPlny --out $Balicky

        Krok 'Zápis do katalogu'
        $a = @('catalog', 'add', $novyBalicek, '--catalog', $Katalog, '--publisher', $Vydavatel, '--changelog', $Zmeny)
        if ($BezpecnostniPoznamky) { $a += @('--security-notes', $BezpecnostniPoznamky) }
        Publish @a
        $zprava = "Vydání $id $ver"
    } else {
        Krok 'Stažení vydání z nabídky'
        Publish catalog yank $id $ver --catalog $Katalog
        $zprava = "Stažení $id $ver z nabídky"
    }

    Krok 'Podpis katalogu'
    Publish catalog sign --catalog $Katalog --key $KlicPlny

    Krok 'Závěrečná kontrola katalogu, podpisů a balíčků'
    Publish catalog validate --catalog $Katalog --trust $SlozkaKlicu

    # --- 5. potvrzení ------------------------------------------------------------------
    Write-Host ''
    Write-Host "Připraveno: $zprava" -ForegroundColor Green
    if ($PSCmdlet.ParameterSetName -eq 'Vydat') {
        Write-Host "  Co je nového: $Zmeny"
        if ($BezpecnostniPoznamky) { Write-Host "  Bezpečnost:   $BezpecnostniPoznamky" }
    }
    $cil = 'na GitHub'
    if ($BezPush) { $cil = 'jen lokálně (bez push)' }
    $odpoved = Read-Host "Zveřejnit $cil? Napište 'ano'"
    if ($odpoved -ne 'ano') { throw 'Vydání nepotvrzeno.' }

    # --- 6. commit -------------------------------------------------------------------
    Krok 'Zápis do Gitu'
    $soubory = @('catalog.json', 'catalog.json.sig')
    if ($novyBalicek) { $soubory += ('balicky/' + (Split-Path $novyBalicek -Leaf)) }
    Spust-Git add -- @soubory
    Spust-Git commit -m $zprava
    $hotovo = $true
} catch {
    Write-Host ''
    Write-Host "Přerušeno: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Vracím změny katalogu…' -ForegroundColor Yellow
    if ($katalogExistoval) { Copy-Item -LiteralPath (Join-Path $zaloha 'catalog.json') -Destination $Katalog -Force }
    elseif (Test-Path -LiteralPath $Katalog) { Remove-Item -LiteralPath $Katalog -Force }
    if ($podpisExistoval) { Copy-Item -LiteralPath (Join-Path $zaloha 'catalog.json.sig') -Destination $Podpis -Force }
    elseif (Test-Path -LiteralPath $Podpis) { Remove-Item -LiteralPath $Podpis -Force }
    if ($novyBalicek -and (Test-Path -LiteralPath $novyBalicek)) { Remove-Item -LiteralPath $novyBalicek -Force }
    $ErrorActionPreference = 'Continue'
    & git -C $Repo reset -q -- catalog.json catalog.json.sig balicky *> $null
    $ErrorActionPreference = 'Stop'
    Write-Host 'Repozitář je ve stavu před spuštěním skriptu.' -ForegroundColor Yellow
} finally {
    Pop-Location
    Remove-Item -LiteralPath $zaloha -Recurse -Force -ErrorAction SilentlyContinue
}
if (-not $hotovo) { exit 1 }

# --- 7. push -------------------------------------------------------------------------
if ($BezPush) {
    Write-Host ''
    Write-Host 'Commit je připravený lokálně. Zveřejníte ho příkazem: git push' -ForegroundColor Green
    exit 0
}
Krok 'Odeslání na GitHub (git push)'
& git -C $Repo push
if ($LASTEXITCODE -ne 0) {
    Konec 'Odeslání na GitHub selhalo. Commit je uložený lokálně.' 'Zkuste to znovu příkazem: git push (nespouštějte skript znovu).'
}
Write-Host ''
Write-Host "Hotovo: $zprava" -ForegroundColor Green
Write-Host 'Servery vydání uvidí při příští kontrole katalogu (výchozí 1× denně), hned po stisku K'
Write-Host 'v konzoli (5 Nástroje -> Dostupné). GitHub může soubory ještě pár minut cachovat.'
