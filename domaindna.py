#!/usr/bin/env python3

"""
DomainDNA
---------
Una herramienta visual y sencilla de inteligencia de dominios para OSINT educativo.

Versión: 1.1.0
"""

import asyncio
import json
import math
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

try:
    import dns.asyncresolver
except ImportError:
    print("Falta una dependencia: dnspython")
    raise SystemExit(1)


APP_NAME = "DomainDNA"
VERSION = "1.1.0"

console = Console()

BANNER = r"""
      ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
      ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
      ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
      ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
      ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
      ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝

                D O M A I N  D N A
     Escáner de Inteligencia de Dominios v1.1
"""


def clean_domain(value: str) -> str:
    value = value.strip().lower()

    if "://" in value:
        value = urlparse(value).hostname or value

    value = value.split("/")[0]
    value = value.split(":")[0]
    value = value.rstrip(".")

    return value


def valid_domain(domain: str) -> bool:
    if len(domain) > 253 or "." not in domain:
        return False

    return bool(
        re.fullmatch(
            r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
            domain,
            re.IGNORECASE,
        )
    )


async def dns_records(domain: str):
    resolver = dns.asyncresolver.Resolver()

    results = {}

    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = await resolver.resolve(domain, record_type)

            values = []

            for answer in answers:
                values.append(str(answer).strip('"'))

            results[record_type] = values

        except Exception:
            results[record_type] = []

    return results


async def web_scan(domain: str):
    result = {
        "http_status": None,
        "https_status": None,
        "http_url": f"http://{domain}",
        "https_url": f"https://{domain}",
        "server": None,
        "content_type": None,
        "headers": {},
    }

    headers = {
        "User-Agent": "DomainDNA/1.1 (+https://github.com/Spyk3r)"
    }

    async with httpx.AsyncClient(
        timeout=8,
        follow_redirects=True,
        headers=headers,
        verify=True,
    ) as client:

        for scheme in ("http", "https"):
            try:
                response = await client.get(
                    f"{scheme}://{domain}"
                )

                if scheme == "http":
                    result["http_status"] = response.status_code
                else:
                    result["https_status"] = response.status_code

                if scheme == "https":
                    important = (
                        "server",
                        "content-type",
                        "strict-transport-security",
                        "content-security-policy",
                        "x-frame-options",
                        "x-content-type-options",
                        "referrer-policy",
                        "permissions-policy",
                    )

                    result["headers"] = {
                        key: response.headers.get(key)
                        for key in important
                        if response.headers.get(key)
                    }

                    result["server"] = response.headers.get("server")
                    result["content_type"] = response.headers.get(
                        "content-type"
                    )

            except Exception:
                pass

    return result


def tls_scan(domain: str):
    result = {
        "subject": None,
        "issuer": None,
        "expires": None,
        "days_remaining": None,
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=8,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain,
            ) as secure_sock:

                certificate = secure_sock.getpeercert()

        subject_parts = []

        for group in certificate.get("subject", ()):
            for key, value in group:
                if key == "commonName":
                    subject_parts.append(value)

        issuer_parts = []

        for group in certificate.get("issuer", ()):
            for key, value in group:
                if key == "organizationName":
                    issuer_parts.append(value)
                elif key == "commonName":
                    issuer_parts.append(value)

        expires = certificate.get("notAfter")

        result["subject"] = ", ".join(subject_parts) or None
        result["issuer"] = ", ".join(issuer_parts) or None
        result["expires"] = expires

        if expires:
            expiry = datetime.strptime(
                expires,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

            result["days_remaining"] = max(
                0,
                (expiry - datetime.now(timezone.utc)).days,
            )

    except Exception:
        pass

    return result


def security_score(web, tls):
    score = 0
    checks = []

    https = web["https_status"] is not None

    checks.append(
        ("HTTPS", https)
    )

    if https:
        score += 30

    hsts = "strict-transport-security" in web["headers"]
    csp = "content-security-policy" in web["headers"]
    xfo = "x-frame-options" in web["headers"]
    xcto = "x-content-type-options" in web["headers"]
    referrer = "referrer-policy" in web["headers"]

    for name, value, points in (
        ("HSTS", hsts, 20),
        ("Content-Security-Policy", csp, 20),
        ("X-Frame-Options", xfo, 10),
        ("X-Content-Type-Options", xcto, 10),
        ("Referrer-Policy", referrer, 10),
    ):
        checks.append((name, value))

        if value:
            score += points

    return min(score, 100), checks


def status_text(status):
    if status is None:
        return "[dim]N/D[/dim]"

    if 200 <= status < 300:
        return f"[green]{status}[/green]"

    if 300 <= status < 400:
        return f"[yellow]{status}[/yellow]"

    return f"[red]{status}[/red]"


def print_dns(records):
    table = Table(
        title="REGISTROS DNS",
        expand=True,
    )

    table.add_column("Tipo", style="cyan", width=10)
    table.add_column("Valor")

    for record_type, values in records.items():
        if values:
            for value in values:
                table.add_row(record_type, value)
        else:
            table.add_row(record_type, "[dim]No encontrado[/dim]")

    console.print(table)


def print_web(web):
    table = Table(
        title="INTELIGENCIA WEB",
        expand=True,
    )

    table.add_column("Propiedad", style="cyan")
    table.add_column("Valor")

    table.add_row(
        "HTTP",
        status_text(web["http_status"]),
    )

    table.add_row(
        "HTTPS",
        status_text(web["https_status"]),
    )

    table.add_row(
        "Servidor",
        web["server"] or "[dim]Desconocido[/dim]",
    )

    table.add_row(
        "Content-Type",
        web["content_type"] or "[dim]Desconocido[/dim]",
    )

    console.print(table)


def print_tls(tls):
    table = Table(
        title="TLS / CERTIFICADO",
        expand=True,
    )

    table.add_column("Propiedad", style="cyan")
    table.add_column("Valor")

    table.add_row(
        "Sujeto",
        tls["subject"] or "[dim]No disponible[/dim]",
    )

    table.add_row(
        "Emisor",
        tls["issuer"] or "[dim]No disponible[/dim]",
    )

    table.add_row(
        "Expira",
        tls["expires"] or "[dim]No disponible[/dim]",
    )

    if tls["days_remaining"] is not None:
        days = tls["days_remaining"]

        if days > 30:
            style = "green"
        elif days > 7:
            style = "yellow"
        else:
            style = "red"

        table.add_row(
            "Días restantes",
            f"[{style}]{days}[/{style}]",
        )

    console.print(table)


def print_security(web, tls):
    score, checks = security_score(
        web,
        tls,
    )

    if score >= 80:
        score_style = "green"
    elif score >= 50:
        score_style = "yellow"
    else:
        score_style = "red"

    console.print(
        Panel(
            f"[bold {score_style}]Puntaje de seguridad: "
            f"{score}/100[/bold {score_style}]",
            title="CABECERAS DE SEGURIDAD",
            border_style=score_style,
        )
    )

    table = Table(expand=True)

    table.add_column("Verificación", style="cyan")
    table.add_column("Estado")

    for name, enabled in checks:
        table.add_row(
            name,
            "[green]✓ Presente[/green]"
            if enabled
            else "[red]✗ Ausente[/red]",
        )

    console.print(table)


def print_ips(domain, records):
    ips = records.get("A", []) + records.get("AAAA", [])

    table = Table(
        title="RED",
        expand=True,
    )

    table.add_column("Dominio", style="cyan")
    table.add_column("Dirección IP")

    if ips:
        for ip in ips:
            table.add_row(domain, ip)
    else:
        table.add_row(
            domain,
            "[dim]No se encontraron registros de dirección[/dim]",
        )

    console.print(table)


def export_json(domain, records, web, tls, score, elapsed, filename):
    data = {
        "tool": APP_NAME,
        "version": VERSION,
        "domain": domain,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "duration_seconds": round(elapsed, 2),
        "dns": records,
        "web": web,
        "tls": tls,
        "security_score": score,
    }

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False,
        )

    console.print(
        f"\n[green][+] Reporte JSON guardado:[/green] {filename}"
    )


# ──────────────────────────────────────────────────────────────
# Animación de doble hélice de ADN
# ──────────────────────────────────────────────────────────────

DNA_WIDTH = 26
DNA_HEIGHT = 12
DNA_AMPLITUDE = (DNA_WIDTH // 2) - 2
DNA_MID = DNA_WIDTH // 2
BASE_PAIR_COLORS = [
    ("bold cyan", "bold magenta"),
    ("bold bright_cyan", "bold bright_magenta"),
]


def render_dna_frame(phase: float) -> str:
    """Genera un cuadro de una hélice de ADN girando, fila por fila,
    usando una onda senoidal para desplazar cada hebra."""

    lines = []

    for row in range(DNA_HEIGHT):
        angle = phase + row * 0.55
        offset = DNA_AMPLITUDE * math.sin(angle)
        left = round(DNA_MID - offset)
        right = round(DNA_MID + offset)

        left_color, right_color = BASE_PAIR_COLORS[row % 2]

        chars = [" "] * DNA_WIDTH

        lo, hi = min(left, right), max(left, right)

        # Los "peldaños" de la escalera solo se ven cuando las
        # hebras están lo bastante separadas (simula la rotación 3D).
        if hi - lo > 1:
            rung_char = "─" if (hi - lo) > 3 else "·"
            for x in range(lo + 1, hi):
                chars[x] = f"[dim white]{rung_char}[/dim white]"

        left = max(0, min(DNA_WIDTH - 1, left))
        right = max(0, min(DNA_WIDTH - 1, right))

        node = "●" if (hi - lo) > 3 else "◆"

        chars[left] = f"[{left_color}]{node}[/{left_color}]"
        chars[right] = f"[{right_color}]{node}[/{right_color}]"

        lines.append("".join(chars))

    return "\n".join(lines)


async def animate_dna(stop_event):
    phase = 0.0

    with Live(
        console=console,
        refresh_per_second=15,
        transient=True,
    ) as live:

        while not stop_event.is_set():
            frame = render_dna_frame(phase)
            phase += 0.28

            live.update(
                Panel(
                    frame + "\n\n[dim]Analizando la estructura del dominio...[/dim]",
                    title="[bold cyan]ADN del dominio[/bold cyan]",
                    border_style="cyan",
                    padding=(0, 3),
                )
            )

            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=1 / 15,
                )
            except asyncio.TimeoutError:
                pass


async def perform_scan(domain):
    stop_event = asyncio.Event()

    animation_task = asyncio.create_task(
        animate_dna(stop_event)
    )

    start = time.perf_counter()

    try:
        records, web = await asyncio.gather(
            dns_records(domain),
            web_scan(domain),
        )

        tls = await asyncio.to_thread(
            tls_scan,
            domain,
        )

    finally:
        stop_event.set()

        try:
            await animation_task
        except asyncio.CancelledError:
            pass

    elapsed = time.perf_counter() - start

    return records, web, tls, elapsed


def show_welcome():
    console.clear()
    console.print(
        Text(
            BANNER,
            style="bold cyan",
        )
    )

    console.print(
        Panel(
            "[bold white]Mapea el ADN público de un dominio.[/bold white]\n"
            "[dim]DNS • Web • TLS • Cabeceras de seguridad[/dim]",
            border_style="cyan",
        )
    )

    console.print()


def ask_domain():
    while True:
        domain = console.input(
            "[bold cyan]➜ Ingresa el dominio a analizar: [/bold cyan]"
        ).strip()

        domain = clean_domain(domain)

        if valid_domain(domain):
            return domain

        console.print(
            "[red]Dominio inválido.[/red] "
            "Ejemplo: example.com\n"
        )


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    """Pide una respuesta Sí/No al usuario, mostrando siempre las
    opciones (S/N) y validando lo que se escriba."""

    suffix = "(S/n)" if default else "(s/N)"
    yes_values = {"s", "si", "sí", "y", "yes"}
    no_values = {"n", "no"}

    while True:
        answer = console.input(
            f"[bold cyan]{prompt} {suffix}: [/bold cyan]"
        ).strip().lower()

        if answer == "":
            return default

        if answer in yes_values:
            return True

        if answer in no_values:
            return False

        console.print(
            "[red]Respuesta no válida.[/red] "
            "Escribe [bold]S[/bold] para sí o [bold]N[/bold] para no.\n"
        )


async def main():
    show_welcome()

    domain = ask_domain()

    console.print()

    console.print(
        Panel.fit(
            f"[bold cyan]OBJETIVO[/bold cyan]\n"
            f"[bold white]{domain}[/bold white]\n\n"
            "[dim]Iniciando análisis público del dominio...[/dim]",
            border_style="cyan",
        )
    )

    console.print()

    try:
        records, web, tls, elapsed = await perform_scan(
            domain
        )

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Análisis interrumpido.[/yellow]"
        )
        return

    score, _ = security_score(
        web,
        tls,
    )

    console.print()
    print_dns(records)

    console.print()
    print_ips(domain, records)

    console.print()
    print_web(web)

    console.print()
    print_tls(tls)

    console.print()
    print_security(web, tls)

    console.print()

    console.print(
        Panel.fit(
            f"[green]✓ Análisis completado[/green]\n"
            f"Dominio: [bold]{domain}[/bold]\n"
            f"Tiempo: {elapsed:.2f}s\n"
            f"Puntaje de seguridad: {score}/100",
            border_style="green",
        )
    )

    console.print()

    save = ask_yes_no("¿Exportar resultados a JSON?", default=False)

    if save:
        filename = f"domaindna_{domain.replace('.', '_')}.json"

        export_json(
            domain,
            records,
            web,
            tls,
            score,
            elapsed,
            filename,
        )

    console.print(
        "\n[dim]DomainDNA finalizó. "
        "Solo se consultó información de acceso público.[/dim]\n"
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Adiós.[/yellow]"
        )
