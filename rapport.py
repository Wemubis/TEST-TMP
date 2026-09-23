#!/usr/bin/env python3
"""Fusionne les CSV en un rapport HTML unique, à partir de html.tmpl.

html.tmpl est un template Grype mono-analyse. On le réutilise comme enveloppe
(sa mise en forme et DataTables) et on remplit le tableau nous-mêmes, avec deux
colonnes en plus : Machine et Image, ajoutées EN FIN de tableau car le template
référence ses colonnes par index de 0 à 9.

Usage : python3 rapport.py resultats/*.csv
"""
import csv, html, re, sys
from datetime import datetime
from pathlib import Path

TEMPLATE = Path("templates/html.tmpl")
SORTIE = Path("rapport.html")
SEVERITES = ["Critical", "High", "Medium", "Low", "Unknown"]


def lire(chemins):
    lignes = []
    for c in chemins:
        with open(c, encoding="utf-8", newline="") as f:
            lignes += list(csv.DictReader(f))
    lignes.sort(key=lambda l: SEVERITES.index(l["Severity"])
                if l["Severity"] in SEVERITES else 99)
    return lignes


def e(v):
    return html.escape((v or "").strip())


def corps(lignes):
    out = []
    for l in lignes:
        src = e(l["Data Source"])
        vuln = e(l["Vulnerability ID"])
        out.append(
            "<tr>"
            f"<td>{e(l['Package'])}</td><td>{e(l['Version Installed'])}</td>"
            f"<td>{e(l['Type'])}</td>"
            f"<td><a href=\"{src}\">{vuln}</a></td>"
            f"<td>{e(l['Severity'])}</td><td>{e(l['Fix State'])}</td>"
            f"<td>{e(l['Fixed In']) or 'N/A'}</td>"
            f"<td></td><td>{src}</td><td></td>"
            f"<td>{e(l['Machine'])}</td><td>{e(l['Image'])}</td>"
            "</tr>")
    return "\n".join(out)


def main():
    fichiers = sys.argv[1:]
    if not fichiers:
        sys.exit("Usage : python3 rapport.py resultats/*.csv")

    lignes = lire(fichiers)
    page = TEMPLATE.read_text(encoding="utf-8")

    # 1. Retirer le bloc Go de comptage et de filtrage, en tête de fichier.
    page = re.sub(r"\{\{/\* Initialize counters \*/\}\}.*?\n<body>", "<body>",
                  page, count=1, flags=re.S)

    # 2. Remplacer l'en-tête, prévu pour une seule image.
    machines = sorted({l["Machine"] for l in lignes})
    images = sorted({l["Image"] for l in lignes})
    entete = (f'<dl class="report-details">'
              f'<dt>Machines:</dt><dd id="nameValue">{e(", ".join(machines))}</dd>'
              f'<dt>Images:</dt><dd>{len(images)}</dd>'
              f'<dt>Date:</dt><dd><span id="dateElement">'
              f'{datetime.now().isoformat(timespec="seconds")}</span>'
              f'<span id="prettyDateElement" style="display:none"></span></dd></dl>')
    page = re.sub(r'<dl class="report-details">.*?</dl>', lambda _: entete,
                  page, count=1, flags=re.S)

    # 3. Compteurs par sévérité.
    for s in SEVERITES:
        n = sum(1 for l in lignes if l["Severity"] == s)
        page = page.replace("{{ $Count%s }}" % s, str(n))

    # 4. Deux colonnes en plus dans l'en-tête du tableau.
    page = page.replace("<th>PURL</th>",
                        "<th>PURL</th><th>Machine</th><th>Image</th>", 1)

    # 5. Corps du tableau. L'ancrage sur </tbody> est indispensable : la boucle
    #    contient une boucle interne dont le {{- end }} serait pris pour la fin.
    page = re.sub(r"\{\{- range \$FilteredMatches \}\}.*?\{\{- end \}\}\s*</tbody>",
                  lambda _: corps(lignes) + "</tbody>", page, count=1, flags=re.S)

    if "{{" in page:
        print("Attention : directives Go restantes dans la page.", file=sys.stderr)

    SORTIE.write_text(page, encoding="utf-8")
    print(f"{len(lignes)} vulnérabilité(s), {len(images)} image(s), "
          f"{len(machines)} machine(s) -> {SORTIE}")


main()
