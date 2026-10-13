#!/usr/bin/python
# -*- coding: utf-8 -*-

# Module Ansible exécuté sur la capsule : analyse une archive déjà rapatriée,
# écrit un CSV par hôte porteur, puis détruit l'archive.
#
# Le rapatriement n'est plus fait ici : il est confié à podman save puis au
# module fetch, qui empruntent la connexion d'Ansible. Ce module ne s'occupe
# donc plus que de ce qui se passe sur la capsule.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: analyser_image
short_description: Analyse une archive d'image et produit un CSV par hôte
description:
  - Lance Grype sur une archive docker-archive déjà présente sur la capsule.
  - Écrit un CSV par hôte porteur de l'image. Le même résultat d'analyse est
    décliné pour chaque porteur - c'est ce qui permet de savoir quelle
    vulnérabilité touche quelle image sur quelle machine, sans avoir analysé
    l'image autant de fois qu'il y a d'hôtes.
  - Détruit l'archive à la fin, y compris en cas d'échec, pour qu'une seule
    archive existe à la fois sur la capsule.
options:
  archive:
    description: Archive docker-archive à analyser, sur la capsule.
    type: path
    required: true
  reference:
    description: Référence de l'image, telle qu'elle figurera dans le rapport.
    type: str
    required: true
  porteurs:
    description:
      - Hôtes portant cette image - une entrée par hôte, avec nom et cle.
      - nom alimente la colonne Machine, cle nomme le fichier CSV.
    type: list
    elements: dict
    required: true
  repertoire_resultats:
    description: Répertoire où déposer les CSV.
    type: path
    required: true
  gabarit_csv:
    description: Gabarit Grype produisant le CSV.
    type: path
    required: true
  grype:
    description: Chemin du binaire Grype.
    type: str
    default: grype
  delai:
    description: Délai maximal de l'analyse, en secondes.
    type: int
    default: 1800
  purger:
    description: Détruire l'archive après analyse.
    type: bool
    default: true
author:
  - Équipe sécurité conteneurs
'''

EXAMPLES = r'''
- name: Analyser l'archive rapatriée
  vulnscan.scan.analyser_image:
    archive: /var/tmp/vulnscan/a1b2c3d4e5f6.tar
    reference: rhel9:1.4
    porteurs:
      - {nom: srv-prod-01, cle: hote-A}
      - {nom: srv-prod-02, cle: hote-B}
    repertoire_resultats: /var/lib/vulnscan/resultats
    gabarit_csv: templates/template-csv-grype.tmpl
  delegate_to: localhost
'''

RETURN = r'''
constatations:
  description: Nombre de lignes produites par Grype pour cette image.
  returned: success
  type: int
fichiers:
  description: Chemins des CSV écrits.
  returned: success
  type: list
'''

import csv
import io
import os
import subprocess

from ansible.module_utils.basic import AnsibleModule


def ecrire_csv(source, destination, machine, image):
    """Recopie le CSV de Grype en préfixant les colonnes Machine et Image.

    Grype ne connaît ni l'une ni l'autre : il a analysé une archive anonyme.
    Ces deux informations n'existent que côté playbook.

    Le module csv est utilisé des deux côtés plutôt qu'un simple préfixe
    textuel : une valeur contenant une virgule ou un guillemet serait sinon
    mal découpée à la relecture.
    """
    with io.open(source, encoding="utf-8", newline="") as entree:
        lignes = [l for l in csv.reader(entree) if l]

    if not lignes:
        return 0

    with io.open(destination, "w", encoding="utf-8", newline="") as sortie:
        ecrivain = csv.writer(sortie, quoting=csv.QUOTE_ALL)
        ecrivain.writerow(["Machine", "Image"] + lignes[0])
        for ligne in lignes[1:]:
            ecrivain.writerow([machine, image] + ligne)
    return len(lignes) - 1


def main():
    module = AnsibleModule(
        argument_spec=dict(
            archive=dict(type="path", required=True),
            reference=dict(type="str", required=True),
            porteurs=dict(type="list", elements="dict", required=True),
            repertoire_resultats=dict(type="path", required=True),
            gabarit_csv=dict(type="path", required=True),
            grype=dict(type="str", default="grype"),
            delai=dict(type="int", default=1800),
            purger=dict(type="bool", default=True),
        ),
        supports_check_mode=True,
    )

    params = module.params
    archive = params["archive"]
    resultats = params["repertoire_resultats"]

    if module.check_mode:
        module.exit_json(changed=False, constatations=0, fichiers=[])

    if not os.path.isfile(archive):
        module.fail_json(msg="Archive introuvable : %s" % archive)
    if not os.path.isfile(params["gabarit_csv"]):
        module.fail_json(msg="Gabarit CSV introuvable : %s" % params["gabarit_csv"])
    if not os.path.isdir(resultats):
        os.makedirs(resultats)

    brut = os.path.splitext(archive)[0] + ".csv"
    chemin_grype = module.get_bin_path(params["grype"]) or params["grype"]

    environnement = dict(os.environ)
    # La base ne doit pas changer au milieu d'une campagne : les premières et
    # les dernières images ne seraient plus comparables entre elles.
    environnement["GRYPE_DB_AUTO_UPDATE"] = "false"
    environnement["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"

    fichiers = []
    constatations = 0
    try:
        analyse = subprocess.run(
            [chemin_grype, "docker-archive:" + archive,
             "-o", "template", "-t", params["gabarit_csv"], "--file", brut],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environnement, timeout=params["delai"])

        if analyse.returncode != 0:
            module.fail_json(
                msg="Analyse de %s en échec : %s" % (
                    params["reference"],
                    analyse.stderr.decode("utf-8", "replace").strip()[:300]))

        court = os.path.splitext(os.path.basename(archive))[0]
        for porteur in params["porteurs"]:
            destination = os.path.join(
                resultats, "%s_%s.csv" % (porteur.get("cle"), court))
            constatations = ecrire_csv(brut, destination,
                                       porteur.get("nom") or porteur.get("cle"),
                                       params["reference"])
            fichiers.append(destination)

    except subprocess.TimeoutExpired:
        module.fail_json(msg="Analyse de %s : délai dépassé" % params["reference"])
    finally:
        # L'archive part quoi qu'il arrive : c'est ce qui borne l'occupation
        # disque de la capsule à une seule archive, quel que soit le parc.
        if params["purger"]:
            for fichier in (archive, brut):
                if os.path.exists(fichier):
                    os.remove(fichier)

    module.exit_json(changed=True, constatations=constatations, fichiers=fichiers)


if __name__ == "__main__":
    main()
