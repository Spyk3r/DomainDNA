<div align="center">

![DomainDNA](assets/banner.png)

### OSINT Domain Intelligence Scanner

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-informational?style=flat-square)
![License](https://img.shields.io/badge/Use-Educational%20%7C%20OSINT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

</div>

# English

## Description

**DomainDNA** is a domain reconnaissance tool that maps all the public "genetic information" of a website: its DNS records, its web behavior, its TLS certificate, and its security headers.

All the analysis is displayed in clear, colored tables in the terminal, accompanied by a spinning **DNA double helix** animation that runs in the background while the scan is in progress.

The scan combines asynchronous requests (DNS + HTTP/HTTPS in parallel) with a direct socket-based TLS check, so results arrive quickly even when analyzing several aspects of the domain at once.

> **Responsible use:** DomainDNA only queries public information (DNS, HTTP headers, and the TLS certificate exposed by the server itself). It does not exploit vulnerabilities or perform any kind of intrusion.

## Features

|     |                                                                          |
| --- | ------------------------------------------------------------------------ |
|     | DNS record resolution (A, AAAA, MX, NS, TXT, CNAME)                      |
|     | Web intelligence: HTTP/HTTPS status, server, and Content-Type            |
|     | TLS certificate reading (subject, issuer, expiration, days remaining)    |
|     | Security score based on headers (HSTS, CSP, X-Frame-Options...)          |
|     | Parallel DNS + Web scanning with `asyncio` for faster results            |
|     | Custom looping DNA double helix animation while scanning                 |
|     | Export results to JSON with a single confirmation (Y/N)                  |
|     | Fully Spanish-language terminal interface, colored with `rich`           |

## Screenshots

**Scan animation**

![DomainDNA DNA animation](assets/screenshot_dna.png)

**Scan result**

![Domain scan result](assets/screenshot_scan.png)

## Installation

```
git clone https://github.com/Spyk3r/DomainDNA.git
cd DomainDNA
pip install -r requirements.txt
```

### Requirements

- Python 3.9 or higher
- Dependencies listed in `requirements.txt`:
  - `rich`
  - `httpx`
  - `dnspython`

## Usage

```
python3 domaindna.py
```

On Windows:

```
python domaindna.py
```

On startup you'll see the welcome banner and be asked for the domain to analyze:

1. Enter the domain (e.g. `example.com`).
2. DomainDNA launches the DNS, web, and TLS scans in parallel, showing the double helix animation while it works.
3. When finished, the result tables are printed: DNS, network, web, TLS, and security headers.
4. At the end you'll be asked `Export results to JSON? (y/N)`, where you can answer `y` / `n` (or leave it empty to use the default value).

## Information it collects

**DNS**

- A / AAAA records (IPv4 and IPv6 addresses)
- MX records (mail servers)
- NS records (name servers)
- TXT and CNAME records

**Web**

- HTTP and HTTPS status code
- `Server` and `Content-Type` headers
- Security headers present: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

**TLS / Certificate**

- Certificate subject (Common Name) and issuer
- Expiration date and days remaining

**Security score**

- Score from 0 to 100 calculated from active HTTPS and the security headers present

## Compatibility

- Windows 10 / 11 (Windows Terminal / PowerShell)
- Linux (any distro with Python 3.9+)
- macOS
- Termux (Android)

> The DNA animation and colors require a terminal with UTF-8 support. If your terminal doesn't display some characters correctly, try Windows Terminal, iTerm2, or any modern terminal.

## Credits

|||
|-|-|
|**Creator**|Spyk3r|
|**GitHub**|[github.com/Spyk3r](https://github.com/Spyk3r)|
|**Discord**|spyk3r|

<div align="center">

Made with love by **Spyk3r**

</div>

---

# Español

## Descripción

**DomainDNA** es una herramienta de reconocimiento de dominios que mapea toda la "información genética" pública de un sitio web: sus registros DNS, su comportamiento web, su certificado TLS y sus cabeceras de seguridad.

Todo el análisis se muestra en tablas claras y coloreadas en la terminal, acompañado de una animación de una **doble hélice de ADN** que gira mientras el escaneo corre en segundo plano.

El escaneo combina peticiones asíncronas (DNS + HTTP/HTTPS en paralelo) con una verificación TLS directa por socket, así que los resultados llegan rápido incluso analizando varios aspectos del dominio a la vez.

> **Uso responsable:** DomainDNA solo consulta información pública (DNS, cabeceras HTTP y el certificado TLS expuesto por el propio servidor). No explota vulnerabilidades ni realiza ningún tipo de intrusión.

## Características

|     |                                                                          |
| --- | ------------------------------------------------------------------------ |
|     | Resolución de registros DNS (A, AAAA, MX, NS, TXT, CNAME)                |
|     | Inteligencia web: estado HTTP/HTTPS, servidor y Content-Type             |
|     | Lectura del certificado TLS (sujeto, emisor, expiración, días restantes) |
|     | Puntaje de seguridad basado en cabeceras (HSTS, CSP, X-Frame-Options...) |
|     | Escaneo DNS + Web en paralelo con `asyncio` para resultados más rápidos  |
|     | Animación propia de doble hélice de ADN, en loop, mientras se analiza    |
|     | Exportación de resultados a JSON con una sola confirmación (S/N)         |
|     | Interfaz de terminal completamente en español, coloreada con `rich`      |

## Capturas

**Animación de análisis**

![Animación de ADN de DomainDNA](assets/screenshot_dna.png)

**Resultado de un análisis**

![Resultado de análisis de dominio](assets/screenshot_scan.png)

## Instalación

```
git clone https://github.com/Spyk3r/DomainDNA.git
cd DomainDNA
pip install -r requirements.txt
```

### Requisitos

- Python 3.9 o superior
- Las dependencias listadas en `requirements.txt`:
  - `rich`
  - `httpx`
  - `dnspython`

## Uso

```
python3 domaindna.py
```

En Windows:

```
python domaindna.py
```

Al iniciar verás el banner de bienvenida y se te pedirá el dominio a analizar:

1. Ingresa el dominio (por ejemplo `example.com`).
2. DomainDNA lanza el escaneo DNS, web y TLS en paralelo, mostrando la animación de la doble hélice mientras trabaja.
3. Al terminar, se imprimen las tablas de resultados: DNS, red, web, TLS y cabeceras de seguridad.
4. Al final se pregunta `¿Exportar resultados a JSON? (s/N)`, donde puedes responder `s` / `n` (o dejarlo vacío para usar el valor por defecto).

## Información que recolecta

**DNS**

- Registros A / AAAA (direcciones IPv4 e IPv6)
- Registros MX (servidores de correo)
- Registros NS (servidores de nombres)
- Registros TXT y CNAME

**Web**

- Código de estado HTTP y HTTPS
- Cabecera `Server` y `Content-Type`
- Cabeceras de seguridad presentes: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

**TLS / Certificado**

- Sujeto (Common Name) e issuer del certificado
- Fecha de expiración y días restantes

**Puntaje de seguridad**

- Puntaje de 0 a 100 calculado a partir de HTTPS activo y las cabeceras de seguridad presentes

## Compatibilidad

- Windows 10 / 11 (Windows Terminal / PowerShell)
- Linux (cualquier distro con Python 3.9+)
- macOS
- Termux (Android)

> La animación de ADN y los colores requieren una terminal con soporte UTF-8. Si tu terminal no muestra bien algunos caracteres, prueba con Windows Terminal, iTerm2 o cualquier terminal moderna.

## Créditos

|||
|-|-|
|**Creador**|Spyk3r|
|**GitHub**|[github.com/Spyk3r](https://github.com/Spyk3r)|
|**Discord**|spyk3r|

<div align="center">

Hecho con dedicación por **Spyk3r**

</div>
