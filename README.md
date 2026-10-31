# Nástroje pro PyControl

Veřejný katalog nástrojů pro PyControl – agenta pro správu Windows serveru. Servery si odsud načítají
seznam nástrojů a správce je v konzoli serveru instaluje a aktualizuje.

**Bezpečnost nestojí na utajení, ale na podpisu.** Repozitář je veřejný; server přijme katalog i každý balíček
jen tehdy, když je podepsaný soukromým klíčem vlastníka (Ed25519), jehož veřejnou část má server
v `C:\Program Files\PyControl\trust\`. Změna čehokoli bez podpisu → server katalog ani balíček nepoužije.

## Struktura

```text
catalog.json        seznam nástrojů a verzí (vytváří pycontrol-publish, nikdy neupravovat ručně)
catalog.json.sig    podpis katalogu
balicky/*.pctool    podepsané balíčky nástrojů
zdroje/<nastroj>/   zdrojové složky nástrojů (tool.json, tool.py, tests/) – server je nečte
vydat.ps1           vydání nebo stažení verze jedním příkazem
```

`.gitattributes` zakazuje Gitu měnit konce řádků u `catalog.json` a podpisů – jinak by Git for Windows
při commitu změnil bajty a podpis by na serveru přestal platit. Neměňte ho.

## Nastavení serveru

1. Veřejný klíč `pycontrol-release.pub` zkopírovat do `C:\Program Files\PyControl\trust\`.
2. Firewall: odchozí HTTPS na `raw.githubusercontent.com`.
3. Konzole **7 Nastavení → Adresa repozitáře nástrojů**: `https://github.com/rdsjanrudolf/pycontrol`
   (větev `main`).
4. Konzole **5 Nástroje → Dostupné**, klávesa **K** načte katalog.

Server kontroluje nové verze jednou za 24 h (`catalog.check_interval_hours`) a o aktualizacích nainstalovaných
nástrojů pošle zprávu správcům v Telegramu. Instaluje a aktualizuje se **jen v konzoli na serveru**.

## Vydání (na počítači vlastníka)

Jednorázově: Python 3.12+, Git for Windows, `pip install pycontrol-1.2.0-py3-none-any.whl pytest`,
klíč `pycontrol-publish keygen --out C:\Klice --name "Jan – vydání PyControl"`.
Soukromý `.pem` **nikdy** do repozitáře, na server ani do chatu.

```powershell
cd C:\Vyvoj\pycontrol
.\vydat.ps1 sample.hello -Zmeny "První vydání"
```

Skript: `git pull` → kontrola, že verze ještě nebyla vydaná → `validate --run-tests` → `build` (podpis
balíčku) → `catalog add` → `catalog sign` → `catalog validate` → potvrzení „ano“ → commit → `git push`.
Při chybě nebo nepotvrzení vrátí katalog do původního stavu.

Další možnosti:

```powershell
.\vydat.ps1 sample.hello -Zmeny "Oprava X" -BezpecnostniPoznamky "Nové oprávnění Y"
.\vydat.ps1 sample.hello -Zmeny "..." -Klic D:\Klice\pycontrol-release.pem
.\vydat.ps1 sample.hello -Zmeny "..." -BezPush        # commit jen lokálně
.\vydat.ps1 -Stahnout sample.hello -Verze 1.0.1       # stáhnout chybnou verzi z nabídky
```

Verze v `tool.json` se musí při každém vydání zvýšit: oprava `1.0.1`, nová funkce `1.1.0`,
nekompatibilní změna vstupů `2.0.0`.

## Vývojový režim vs. katalog

Na testovacím serveru se nový nástroj zkouší ze složky `tools\_dev\` (vývojový režim). Jádro **přeskočí
vývojovou kopii, pokud je nástroj se stejným ID už nainstalovaný z katalogu**. Proto:

* před instalací z katalogu smazat vývojovou kopii z `_dev` a restartovat službu,
* při zkoušení nové verze nainstalovaného nástroje ho nejdřív v konzoli odebrat (**O**), pak vývojovou kopii
  nahrát do `_dev`; po vydání ji smazat a nainstalovat verzi z katalogu.

## Ukázkový nástroj

`zdroje/sample_hello` (`sample.hello`) je vzorový nástroj z balíku PyControl – jen čte, slouží k ověření celé
cesty vydání → instalace → aktualizace.
