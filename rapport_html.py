#!/usr/bin/python
# -*- coding: utf-8 -*-

# Module Ansible : fusionne les CSV produits par Grype en un rapport HTML.
# Reprend la logique de l'ancien generer-rapport.py, sans dépendance externe.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: rapport_html
short_description: Fusionne des CSV Grype en un rapport HTML unique
description:
  - Lit les CSV produits par Grype, les fusionne et remplit le gabarit HTML
    fourni par Anchore.
  - Ce gabarit est prévu par Grype pour une seule analyse. Le module le
    réutilise comme enveloppe (mise en forme, DataTables, exports) et remplit
    le tableau lui-même, avec deux colonnes supplémentaires, Machine et Image.
  - Ces deux colonnes sont ajoutées en fin de tableau, car le gabarit
    référence ses colonnes par index codé en dur de 0 à 9. Les placer en tête
    décalerait tout et casserait les badges de sévérité ainsi que les liens.
options:
  repertoire_csv:
    description: Répertoire contenant les fichiers .csv à fusionner.
    type: path
    required: true
  gabarit:
    description: Chemin du gabarit HTML (template-html-rapport.tmpl).
    type: path
    required: true
  destination:
    description: Chemin du fichier HTML à produire.
    type: path
    required: true
  severites:
    description: Sévérités retenues dans le rapport.
    type: list
    elements: str
    default: [Critical, High, Medium]
  icones_externes:
    description:
      - À false, remplace les icônes chargées depuis api.iconify.design par du
        texte. Sans accès à ce domaine, les boutons d'export apparaissent comme
        des cases grises et un espace vide précède chaque type de paquet.
    type: bool
    default: false
author:
  - Équipe sécurité conteneurs
'''

EXAMPLES = r'''
- name: Produire le rapport de l'environnement
  vulnscan.scan.rapport_html:
    repertoire_csv: /var/lib/vulnscan/resultats
    gabarit: "{{ playbook_dir }}/templates/template-html-rapport.tmpl"
    destination: /var/lib/vulnscan/rapport.html
  delegate_to: localhost
  run_once: true
'''

RETURN = r'''
vulnerabilites:
  description: Nombre de constatations retenues.
  returned: success
  type: int
machines:
  description: Noms des machines présentes dans le rapport.
  returned: success
  type: list
images:
  description: Références d'images présentes dans le rapport.
  returned: success
  type: list
par_severite:
  description: Décompte par sévérité.
  returned: success
  type: dict
'''

import csv
import datetime
import glob
import html
import io
import os
import re

from ansible.module_utils.basic import AnsibleModule

# Colonnes produites par template-csv-grype.tmpl, plus les deux ajoutées par
# l'étape awk du playbook.
REQUISES = ["Machine", "Image", "Package", "Version Installed", "Type",
            "Vulnerability ID", "Severity", "Fix State", "Fixed In",
            "Data Source"]

ORDRE_SEVERITE = ["Critical", "High", "Medium", "Low", "Unknown"]


def echapper(valeur):
    return html.escape((valeur or "").strip())


def lire_csv(repertoire, severites, module):
    """Charge les CSV, vérifie leur structure, fusionne et trie."""
    fichiers = sorted(glob.glob(os.path.join(repertoire, "*.csv")))
    if not fichiers:
        # En mode simulation, l'étape d'analyse n'a rien produit : l'absence
        # de CSV est attendue et ne doit pas faire échouer le playbook.
        if module.check_mode:
            return [], 0
        module.fail_json(
            msg="Aucun fichier CSV dans %s. L'étape d'analyse a-t-elle "
                "produit des résultats ?" % repertoire)

    lignes = []
    for chemin in fichiers:
        with io.open(chemin, encoding="utf-8", newline="") as flux:
            lecteur = csv.DictReader(flux)
            entete = lecteur.fieldnames or []

            manquantes = [c for c in REQUISES if c not in entete]
            if manquantes:
                module.fail_json(
                    msg="%s : colonnes absentes %s (en-tête lu : %s)"
                        % (chemin, manquantes, entete))

            lues = list(lecteur)

            # Colonne Machine vide ou littérale : signe que l'étape awk du
            # playbook n'a pas fonctionné (typiquement NR=1 au lieu de NR==1).
            valeurs = set((l.get("Machine") or "").strip() for l in lues)
            if lues and valeurs <= set(["", "Machine"]):
                module.fail_json(
                    msg="%s : la colonne Machine ne contient pas de nom de "
                        "machine mais %s. Vérifier le bloc awk du playbook "
                        "(NR==1 et non NR=1)." % (chemin, sorted(valeurs)))

            lignes.extend(lues)

    retenues = [l for l in lignes if (l.get("Severity") or "") in severites]
    retenues.sort(key=lambda l: (
        ORDRE_SEVERITE.index(l["Severity"])
        if l["Severity"] in ORDRE_SEVERITE else 99,
        l.get("Machine", ""), l.get("Image", ""), l.get("Package", "")))
    return retenues, len(fichiers)


def corps_tableau(lignes):
    """Produit les lignes du tableau, 12 colonnes dans l'ordre du gabarit."""
    sortie = []
    for l in lignes:
        source = echapper(l.get("Data Source"))
        vuln = echapper(l.get("Vulnerability ID"))
        lien = '<a href="%s">%s</a>' % (source, vuln) if source else vuln
        sortie.append(
            "<tr>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td><td>%s</td>"
            "<td></td><td>%s</td><td></td>"
            "<td>%s</td><td>%s</td>"
            "</tr>" % (
                echapper(l.get("Package")),
                echapper(l.get("Version Installed")),
                echapper(l.get("Type")),
                lien,
                echapper(l.get("Severity")),
                echapper(l.get("Fix State")),
                echapper(l.get("Fixed In")) or "N/A",
                source,                       # Related URLs
                echapper(l.get("Machine")),
                echapper(l.get("Image")),
            ))
    return "\n".join(sortie)


def construire(gabarit, lignes, nb_fichiers, icones, horodatage):
    page = gabarit

    # 1. Retirer le bloc Go qui initialise les compteurs et filtre les matches.
    page, n = re.subn(r"\{\{/\* Initialize counters \*/\}\}.*?\n<body>",
                      "<body>", page, count=1, flags=re.S)
    if n != 1:
        return None, "bloc d'initialisation Go introuvable dans le gabarit"

    # 2. Remplacer l'en-tête, prévu pour une seule image.
    machines = sorted(set(l.get("Machine", "") for l in lignes))
    images = sorted(set(l.get("Image", "") for l in lignes))
    entete = (
        '<dl class="report-details">'
        '<dt>Machines:</dt><dd id="nameValue">%s</dd>'
        '<dt>Images:</dt><dd>%d</dd>'
        '<dt>Analyses:</dt><dd>%d</dd>'
        '<dt>Date:</dt><dd><span id="dateElement">%s</span>'
        '<span id="prettyDateElement" style="display:none"></span></dd>'
        '</dl>' % (echapper(", ".join(machines)), len(images),
                   nb_fichiers, echapper(horodatage)))
    page, n = re.subn(r'<dl class="report-details">.*?</dl>',
                      lambda _: entete, page, count=1, flags=re.S)
    if n != 1:
        return None, "bloc de métadonnées introuvable dans le gabarit"

    # 3. Compteurs par sévérité.
    comptes = {}
    for sev in ORDRE_SEVERITE:
        comptes[sev] = sum(1 for l in lignes if l.get("Severity") == sev)
        page = page.replace("{{ $Count%s }}" % sev, str(comptes[sev]))

    # 4. Deux colonnes supplémentaires dans l'en-tête du tableau.
    page = page.replace("<th>PURL</th>",
                        "<th>PURL</th><th>Machine</th><th>Image</th>", 1)

    # 5. Corps du tableau. L'ancrage sur </tbody> est indispensable : la boucle
    #    du gabarit contient une boucle interne sur les versions correctives,
    #    dont le {{- end }} serait pris pour la fin du bloc.
    page, n = re.subn(
        r"\{\{- range \$FilteredMatches \}\}.*?\{\{- end \}\}\s*</tbody>",
        lambda _: corps_tableau(lignes) + "</tbody>", page, count=1, flags=re.S)
    if n != 1:
        return None, "boucle du tableau introuvable dans le gabarit"

    # 6. Déclarer les deux colonnes à DataTables.
    page = page.replace(
        "                className: 'none', // Tell Responsive to hide this "
        "column initially\n            },\n        ];",
        "                className: 'none', // Tell Responsive to hide this "
        "column initially\n            },\n"
        "            { name: 'Machine', targets: 10, responsivePriority: 3 },\n"
        "            { name: 'Image',   targets: 11, responsivePriority: 4 },\n"
        "        ];", 1)

    # 7. Remplacer les icônes injoignables par du texte.
    if not icones:
        page = page.replace(
            """text: '<span class="vscode-icons--file-type-pdf2"></span>',""",
            """text: 'PDF',""", 1)
        page = page.replace(
            """text: '<span class="vscode-icons--file-type-excel"></span>',""",
            """text: 'Excel',""", 1)
        # L'élément d'icône du type occupe de la place même vide.
        page = page.replace(
            'return `<span class="pkg-type-cell">${iconHtml}'
            '<span>${data}</span></span>`;',
            'return `<span class="pkg-type-cell">'
            '<span>${data}</span></span>`;', 1)

    restes = re.findall(r"\{\{[^}]*\}\}", page)
    if restes:
        return None, ("directives Go non traitées dans la page : %s. "
                      "Le gabarit a-t-il changé de version ?" % restes[:3])

    return page, comptes


def main():
    module = AnsibleModule(
        argument_spec=dict(
            repertoire_csv=dict(type="path", required=True),
            gabarit=dict(type="path", required=True),
            destination=dict(type="path", required=True),
            severites=dict(type="list", elements="str",
                           default=["Critical", "High", "Medium"]),
            icones_externes=dict(type="bool", default=False),
        ),
        supports_check_mode=True,
    )

    repertoire = module.params["repertoire_csv"]
    chemin_gabarit = module.params["gabarit"]
    destination = module.params["destination"]
    severites = module.params["severites"]
    icones = module.params["icones_externes"]

    # En mode simulation, l'étape d'analyse n'a rien créé : l'absence du
    # répertoire est attendue et ne doit pas faire échouer le playbook.
    if not os.path.isdir(repertoire) and not module.check_mode:
        module.fail_json(msg="Répertoire introuvable : %s" % repertoire)
    if not os.path.isfile(chemin_gabarit):
        module.fail_json(msg="Gabarit introuvable : %s" % chemin_gabarit)

    lignes, nb_fichiers = lire_csv(repertoire, severites, module)

    with io.open(chemin_gabarit, encoding="utf-8") as flux:
        gabarit = flux.read()

    horodatage = datetime.datetime.now().replace(microsecond=0).isoformat()

    page, resultat = construire(gabarit, lignes, nb_fichiers, icones,
                                horodatage)
    if page is None:
        module.fail_json(msg=resultat)

    machines = sorted(set(l.get("Machine", "") for l in lignes))
    images = sorted(set(l.get("Image", "") for l in lignes))

    if module.check_mode:
        module.exit_json(changed=True, vulnerabilites=len(lignes),
                         machines=machines, images=images,
                         par_severite=resultat)

    repertoire_sortie = os.path.dirname(destination)
    if repertoire_sortie and not os.path.isdir(repertoire_sortie):
        os.makedirs(repertoire_sortie)

    with io.open(destination, "w", encoding="utf-8") as flux:
        flux.write(page)

    module.exit_json(changed=True, vulnerabilites=len(lignes),
                     machines=machines, images=images, par_severite=resultat,
                     destination=destination)


if __name__ == "__main__":
    main()
