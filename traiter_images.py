#!/usr/bin/python
# -*- coding: utf-8 -*-

# Module Ansible exécuté sur la capsule : déduplique les images de tous les
# hôtes, puis rapatrie, analyse et purge chacune d'elles, une par une.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: traiter_images
short_description: Rapatrie et analyse les images de conteneurs d'un parc
description:
  - Déduplique les images inventoriées sur l'ensemble des hôtes, puis traite
    chaque image unique une seule fois.
  - Pour chaque image - rapatriement en flux, analyse par Grype, puis écriture
    d'un CSV par hôte porteur.
  - L'archive est détruite avant de passer à l'image suivante. Une seule
    archive existe donc à la fois sur la capsule, quel que soit le nombre
    d'images ou d'hôtes. Traiter toutes les images en parallèle ferait suivre
    l'occupation disque à la taille du parc.
  - Le rapatriement passe par un ssh direct et non par un module de copie - la
    sortie standard de podman save est redirigée vers la capsule, de sorte que
    la machine distante n'écrit rien sur son disque.
  - Un échec sur une image est consigné et le traitement se poursuit - une
    machine éteinte ne doit pas annuler la campagne.
options:
  inventaires:
    description:
      - Un élément par hôte - cle, nom, moteur, cible (user@hote) et images.
    type: list
    elements: dict
    required: true
  repertoire_travail:
    description: Répertoire des archives temporaires, sur la capsule.
    type: path
    required: true
  repertoire_resultats:
    description: Répertoire où déposer les CSV produits.
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
  options_ssh:
    description: Options passées au ssh de rapatriement.
    type: str
    default: '-o BatchMode=yes'
  mot_de_passe_ssh:
    description:
      - Mot de passe SSH. Vide pour une authentification par clé (recommandé).
      - Transmis à sshpass par l'environnement, jamais en ligne de commande -
        il n'apparaît donc pas dans la liste des processus.
    type: str
    default: ''
    no_log: true
  delai_rapatriement:
    description: Délai maximal du rapatriement d'une image, en secondes.
    type: int
    default: 3600
  delai_analyse:
    description: Délai maximal de l'analyse d'une image, en secondes.
    type: int
    default: 1800
author:
  - Équipe sécurité conteneurs
'''

EXAMPLES = r'''
- name: Rapatrier, analyser et purger chaque image
  vulnscan.scan.traiter_images:
    inventaires: "{{ inventaires }}"
    repertoire_travail: /var/tmp/vulnscan
    repertoire_resultats: /var/lib/vulnscan/resultats
    gabarit_csv: "{{ playbook_dir }}/templates/template-csv-grype.tmpl"
  delegate_to: localhost
  run_once: true
'''

RETURN = r'''
images_uniques:
  description: Nombre d'images distinctes traitées.
  returned: always
  type: int
presences:
  description: Nombre total de présences d'images sur le parc.
  returned: always
  type: int
reussites:
  description: Images analysées avec succès.
  returned: always
  type: list
echecs:
  description: Images en échec, avec leur motif.
  returned: always
  type: list
fichiers_csv:
  description: Nombre de CSV produits.
  returned: always
  type: int
'''

import csv
import io
import os
import re
import subprocess

from ansible.module_utils.basic import AnsibleModule


def construire_plan(inventaires):
    """Déduplique les images par identifiant.

    Deux hôtes portant le même identifiant portent une image strictement
    identique : une seule analyse fait foi. Le premier hôte rencontré sert de
    source ; tous les porteurs sont conservés, car ce sont eux qui
    apparaîtront dans le rapport.
    """
    plan = {}
    presences = 0
    for hote in inventaires:
        porteur = {"nom": hote.get("nom") or hote.get("cle"),
                   "cle": hote.get("cle")}
        for image in hote.get("images") or []:
            presences += 1
            identifiant = image["id"]
            if identifiant in plan:
                plan[identifiant]["porteurs"].append(porteur)
                continue
            plan[identifiant] = {
                "id": identifiant,
                "court": identifiant[:12],
                # Seule la partie après le dernier / est conservée pour
                # l'affichage : le registre alourdit la lecture du rapport.
                "ref": os.path.basename(image["ref"]),
                "ref_complete": image["ref"],
                "moteur": hote.get("moteur") or "podman",
                "cible": hote.get("cible"),
                "source": hote.get("cle"),
                "porteurs": [porteur],
            }
    return plan, presences


def rapatrier(module, entree, archive, params):
    """Rapatrie l'archive de l'image, sans rien écrire sur la machine distante.

    podman save écrit sur sa sortie standard : le flux traverse SSH et
    l'archive se matérialise sur la capsule.
    """
    # docker save refuse --format ; podman l'exige pour garantir le format
    # attendu par Grype.
    format_save = "--format docker-archive" if entree["moteur"] == "podman" else ""
    distante = "%s save %s '%s'" % (entree["moteur"], format_save, entree["id"])

    commande = []
    environnement = dict(os.environ)
    if params["mot_de_passe_ssh"]:
        commande.append("sshpass")
        commande.append("-e")
        environnement["SSHPASS"] = params["mot_de_passe_ssh"]

    # -n : ssh ne doit pas consommer l'entrée standard du module.
    commande += ["ssh", "-n"] + params["options_ssh"].split() \
                + [entree["cible"], distante]

    with io.open(archive, "wb") as flux:
        processus = subprocess.Popen(commande, stdout=flux,
                                     stderr=subprocess.PIPE,
                                     env=environnement)
        _, erreur = processus.communicate(timeout=params["delai_rapatriement"])

    if processus.returncode != 0:
        return "rapatriement depuis %s : %s" % (
            entree["cible"], (erreur or b"").decode("utf-8", "replace").strip()[:200])

    # Une archive tronquée par une coupure reste lisible sur ses premiers
    # octets : on vérifie qu'elle se déroule entièrement.
    verif = subprocess.run(["tar", "-tf", archive],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if verif.returncode != 0:
        return "archive illisible, transfert incomplet"
    return None


def ecrire_csv(source, destination, machine, image):
    """Recopie le CSV de Grype en préfixant les colonnes Machine et Image.

    Grype ne connaît ni l'une ni l'autre : il a analysé une archive anonyme.
    Ces deux informations n'existent que côté playbook.
    """
    with io.open(source, encoding="utf-8", newline="") as entree:
        lecteur = csv.reader(entree)
        lignes = [l for l in lecteur if l]

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
            inventaires=dict(type="list", elements="dict", required=True),
            repertoire_travail=dict(type="path", required=True),
            repertoire_resultats=dict(type="path", required=True),
            gabarit_csv=dict(type="path", required=True),
            grype=dict(type="str", default="grype"),
            options_ssh=dict(type="str", default="-o BatchMode=yes"),
            mot_de_passe_ssh=dict(type="str", default="", no_log=True),
            delai_rapatriement=dict(type="int", default=3600),
            delai_analyse=dict(type="int", default=1800),
        ),
        supports_check_mode=True,
    )

    params = module.params
    travail = params["repertoire_travail"]
    resultats = params["repertoire_resultats"]

    if not os.path.isfile(params["gabarit_csv"]):
        module.fail_json(msg="Gabarit CSV introuvable : %s" % params["gabarit_csv"])

    plan, presences = construire_plan(params["inventaires"])

    if module.check_mode:
        module.exit_json(changed=False, images_uniques=len(plan),
                         presences=presences, reussites=[], echecs=[],
                         fichiers_csv=0,
                         plan=[v["ref"] for v in plan.values()])

    for repertoire in (travail, resultats):
        if not os.path.isdir(repertoire):
            os.makedirs(repertoire)

    chemin_grype = module.get_bin_path(params["grype"]) or params["grype"]

    environnement = dict(os.environ)
    # La base ne doit pas changer au milieu d'une campagne : les premières et
    # les dernières images ne seraient plus comparables entre elles.
    environnement["GRYPE_DB_AUTO_UPDATE"] = "false"
    environnement["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"

    reussites, echecs = [], []
    nb_csv = 0

    # Les images sont traitées une par une, et l'archive détruite avant de
    # passer à la suivante.
    for entree in plan.values():
        archive = os.path.join(travail, entree["court"] + ".tar")
        brut = os.path.join(travail, entree["court"] + ".csv")

        try:
            motif = rapatrier(module, entree, archive, params)
            if motif:
                echecs.append({"image": entree["ref"], "motif": motif})
                continue

            analyse = subprocess.run(
                [chemin_grype, "docker-archive:" + archive,
                 "-o", "template", "-t", params["gabarit_csv"],
                 "--file", brut],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environnement, timeout=params["delai_analyse"])
            if analyse.returncode != 0:
                echecs.append({
                    "image": entree["ref"],
                    "motif": "analyse : " + analyse.stderr.decode(
                        "utf-8", "replace").strip()[:200]})
                continue

            # Le même résultat d'analyse est décliné pour chaque hôte porteur :
            # c'est ce qui permet de savoir quelle vulnérabilité touche quelle
            # image sur quelle machine, sans avoir analysé l'image N fois.
            for porteur in entree["porteurs"]:
                destination = os.path.join(
                    resultats, "%s_%s.csv" % (porteur["cle"], entree["court"]))
                ecrire_csv(brut, destination, porteur["nom"], entree["ref"])
                nb_csv += 1

            reussites.append({"image": entree["ref"],
                              "porteurs": len(entree["porteurs"])})

        except subprocess.TimeoutExpired:
            echecs.append({"image": entree["ref"], "motif": "délai dépassé"})
        except Exception as exc:
            echecs.append({"image": entree["ref"], "motif": str(exc)[:200]})
        finally:
            # L'archive part quoi qu'il arrive, y compris après un échec.
            for fichier in (archive, brut):
                if os.path.exists(fichier):
                    os.remove(fichier)

    module.exit_json(changed=bool(reussites), images_uniques=len(plan),
                     presences=presences, reussites=reussites, echecs=echecs,
                     fichiers_csv=nb_csv)


if __name__ == "__main__":
    main()
