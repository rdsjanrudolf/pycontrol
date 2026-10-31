"""Vzorový nástroj – šablona pro nové nástroje.

Pravidla:
* ``execute(ctx, inp)`` dostane už ověřený vstup podle ``input_schema``.
* Vrací slovník (JSON). Uživateli srozumitelnou chybu hlaste přes ``ToolError``.
* Pro log používejte ``ctx.log`` – záznam dostane korelační ID úlohy.
* Nástroj nemá přístup k tajemstvím jádra a nesmí obcházet potvrzení.
"""

import datetime as dt

from pycontrol.tools.sdk import ToolContext, ToolError


def execute(ctx: ToolContext, inp: dict) -> dict:
    jmeno = inp["jmeno"].strip()
    if not jmeno:
        raise ToolError("Jméno nesmí být prázdné.", code="invalid_input")
    ctx.log.info("Zdravím %s", jmeno)
    pozdrav = f"Ahoj, {jmeno}! Tady PyControl."
    return {
        "pozdrav": pozdrav,
        "cas_serveru": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "pozadal": ctx.requester,
        "verze_nastroje": "1.0.1",
        "summary": pozdrav,
    }
