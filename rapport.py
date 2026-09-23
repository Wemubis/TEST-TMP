#!/usr/bin/env python3

import csv, html, re, sys
from datetime import datetime
from pathlib import Path

TEMPLATE = Path("templates/html.tmpl")
SORTIE = Path("rapport.html")
SEVERITES = ["Critical", "High", "Medium", "Low", "Unknown"]

ICONES_EXTERNES = False

# Colonnes produites par csv.tmpl, plus les deux ajoutées par le script.
REQUISES = ["Machine", "Image", "Package", "Version Installed", "Type",
            "Vulnerability ID", "Severity", "Fix State", "Fixed In", "Data Source"]


def lire(chemins):
    lignes = []
    for c in chemins:
        with open(c, encoding="utf-8", newline="") as f:
            lecteur = csv.DictReader(f)          # format CSV standard
            entete = lecteur.fieldnames or []

            manquantes = [col for col in REQUISES if col not in entete]
            if manquantes:
                sys.exit(f"{c} : colonnes absentes {manquantes}\n"
                         f"  en-tete lu : {entete}")

            lues = list(lecteur)

            # Valeurs vides ou littérales : signe que l'étape awk du script
            # de scan n'a pas fonctionné (typiquement NR=1 au lieu de NR==1).
            suspectes = {(l.get("Machine") or "").strip() for l in lues}
            if lues and suspectes <= {"", "Machine"}:
                sys.exit(f"{c} : la colonne Machine ne contient pas de nom de "
                         f"machine mais {suspectes}.\n"
                         f"  -> verifier le bloc awk du script de scan "
                         f"(NR==1 et non NR=1)")
            lignes += lues

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
        lien = f'<a href="{src}">{vuln}</a>' if src else vuln
        out.append(
            "<tr>"
            f"<td>{e(l['Package'])}</td><td>{e(l['Version Installed'])}</td>"
            f"<td>{e(l['Type'])}</td>"
            f"<td>{lien}</td>"
            f"<td>{e(l['Severity'])}</td><td>{e(l['Fix State'])}</td>"
            f"<td>{e(l['Fixed In']) or 'N/A'}</td>"
            f"<td></td>"                      # Description : absente du CSV
            f"<td>{src}</td>"                 # Related URLs
            f"<td></td>"                      # PURL : absente du CSV
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
              f'<dt>Images:</dt><dd>{len(images)} : {e(", ".join(images))}</dd>'
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

    # 6. Déclarer les deux colonnes à DataTables.
    page = page.replace(
        "                className: 'none', // Tell Responsive to hide this column initially\n"
        "            },\n        ];",
        "                className: 'none', // Tell Responsive to hide this column initially\n"
        "            },\n"
        "            { name: 'Machine', targets: 10, responsivePriority: 3 },\n"
        "            { name: 'Image',   targets: 11, responsivePriority: 4 },\n"
        "        ];", 1)

    # 7. Remplacer les icônes injoignables par du texte.
    if not ICONES_EXTERNES:
        page = page.replace(
            """text: '<span class="vscode-icons--file-type-pdf2"></span>',""",
            """text: 'PDF',""", 1)
        page = page.replace(
            """text: '<span class="vscode-icons--file-type-excel"></span>',""",
            """text: 'Excel',""", 1)
        # L'élément d'icône du type occupe de la place même vide : on le retire.
        page = page.replace(
            'return `<span class="pkg-type-cell">${iconHtml}<span>${data}</span></span>`;',
            'return `<span class="pkg-type-cell"><span>${data}</span></span>`;', 1)

    if "{{" in page:
        print("Attention : directives Go restantes dans la page.", file=sys.stderr)

    SORTIE.write_text(page, encoding="utf-8")
    print(f"{len(lignes)} vulnérabilité(s), {len(images)} image(s), "
          f"{len(machines)} machine(s) -> {SORTIE}")


main()
