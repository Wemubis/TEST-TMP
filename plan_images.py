#!/usr/bin/python
# -*- coding: utf-8 -*-

# Module Ansible exécuté sur la capsule : déduplique les images inventoriées
# sur l'ensemble des hôtes et produit le plan de traitement.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: plan_images
short_description: Déduplique les images d'un parc et produit le plan d'analyse
description:
  - Rassemble les inventaires de tous les hôtes et regroupe les images par
    identifiant.
  - Deux hôtes portant le même identifiant portent une image strictement
    identique - une seule analyse fait foi. Le premier hôte rencontré sert de
    source ; tous les porteurs sont conservés, car ce sont eux qui
    apparaîtront dans le rapport.
  - Ne touche à rien - le module se contente de calculer. Le plan qu'il
    retourne est ensuite parcouru par le playbook.
options:
  inventaires:
    description:
      - Un élément par hôte - cle, nom, moteur et images.
    type: list
    elements: dict
    required: true
author:
  - Équipe sécurité conteneurs
'''

EXAMPLES = r'''
- name: Construire le plan dédoublonné
  vulnscan.scan.plan_images:
    inventaires: "{{ inventaires }}"
  register: plan
  delegate_to: localhost
  run_once: true
'''

RETURN = r'''
images:
  description: Une entrée par image unique, à parcourir par le playbook.
  returned: success
  type: list
  sample:
    - id: a1b2c3d4e5f6...
      court: a1b2c3d4e5f6
      ref: rhel9:1.4
      source: hote-A
      moteur: podman
      porteurs: [{nom: srv-01, cle: hote-A}]
images_uniques:
  description: Nombre d'images distinctes.
  returned: success
  type: int
presences:
  description: Nombre total de présences sur le parc.
  returned: success
  type: int
'''

import os

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(
        argument_spec=dict(
            inventaires=dict(type="list", elements="dict", required=True),
        ),
        supports_check_mode=True,
    )

    plan = {}
    presences = 0

    for hote in module.params["inventaires"]:
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
                "source": hote.get("cle"),
                "porteurs": [porteur],
            }

    images = sorted(plan.values(), key=lambda e: e["ref"])
    module.exit_json(changed=False, images=images,
                     images_uniques=len(images), presences=presences)


if __name__ == "__main__":
    main()
