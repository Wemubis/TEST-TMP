#!/usr/bin/python
# -*- coding: utf-8 -*-

# Module Ansible exécuté sur chaque hôte : détecte le moteur de conteneurs et
# inventorie les images présentes. Strictement en lecture seule.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: inventaire_images
short_description: Inventorie les images de conteneurs d'un hôte
description:
  - Détecte le moteur de conteneurs disponible, puis liste les images taguées
    avec leur identifiant.
  - Strictement en lecture seule : aucune écriture sur l'hôte, aucun transfert.
  - L'identifiant est normalisé (préfixe sha256 retiré) car podman le pose sur
    certaines commandes et pas sur d'autres, ce qui empêcherait de reconnaître
    une même image vue depuis deux hôtes.
options:
  moteurs:
    description:
      - Moteurs recherchés, dans l'ordre de préférence.
      - podman en premier car le paquet podman-docker installe une commande
        docker qui n'est en réalité que podman.
    type: list
    elements: str
    default: [podman, docker]
  exclusions:
    description:
      - Expressions régulières appliquées à la référence complète de l'image.
      - Les images non taguées sont écartées d'office, sans configuration.
    type: list
    elements: str
    default: []
author:
  - Équipe sécurité conteneurs
'''

EXAMPLES = r'''
- name: Inventorier les images de l'hôte
  vulnscan.scan.inventaire_images:
    exclusions:
      - '^localhost/build-'
  register: inventaire
'''

RETURN = r'''
trouve:
  description: Vrai si un moteur de conteneurs a été détecté.
  returned: always
  type: bool
moteur:
  description: Moteur retenu (podman ou docker), vide si aucun.
  returned: always
  type: str
images:
  description: Images taguées, dédoublonnées par identifiant.
  returned: success
  type: list
  sample: [{"id": "a1b2c3...", "ref": "registry/socle:1.4"}]
ecartees:
  description: Décompte des images écartées, par motif.
  returned: success
  type: dict
'''

import re

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(
        argument_spec=dict(
            moteurs=dict(type="list", elements="str",
                         default=["podman", "docker"]),
            exclusions=dict(type="list", elements="str", default=[]),
        ),
        supports_check_mode=True,
    )

    moteurs = module.params["moteurs"]
    exclusions = module.params["exclusions"]

    # --- Détection du moteur ------------------------------------------------
    moteur = ""
    chemin = None
    for candidat in moteurs:
        trouve = module.get_bin_path(candidat)
        if trouve:
            moteur, chemin = candidat, trouve
            break

    if not moteur:
        module.exit_json(changed=False, trouve=False, moteur="",
                         images=[], ecartees={})

    # --- Liste des images ---------------------------------------------------
    gabarit = "{{.ID}}|{{.Repository}}:{{.Tag}}"
    rc, sortie, erreur = module.run_command(
        [chemin, "images", "--no-trunc", "--format", gabarit])
    if rc != 0:
        module.fail_json(
            msg="%s images a échoué (code %d) : %s" % (moteur, rc, erreur.strip()),
            moteur=moteur)

    # --- Filtrage et dédoublonnage -----------------------------------------
    motifs = [re.compile(m) for m in exclusions]
    images = []
    vus = set()
    ecartees = {"non_taguees": 0, "par_motif": []}

    for ligne in sortie.splitlines():
        parties = ligne.strip().split("|")
        if len(parties) != 2:
            continue
        identifiant, reference = parties

        if "<none>" in reference:
            ecartees["non_taguees"] += 1
            continue
        if any(m.search(reference) for m in motifs):
            ecartees["par_motif"].append(reference)
            continue

        # podman pose le préfixe sha256 sur `images` mais pas sur
        # `image inspect` : sans normalisation, une même image ne serait pas
        # reconnue d'un hôte à l'autre.
        identifiant = re.sub(r"^sha256:", "", identifiant)

        # Une image portant plusieurs tags sort plusieurs fois.
        if identifiant in vus:
            continue
        vus.add(identifiant)
        images.append({"id": identifiant, "ref": reference})

    module.exit_json(changed=False, trouve=True, moteur=moteur,
                     images=images, ecartees=ecartees)


if __name__ == "__main__":
    main()
