#!/usr/bin/env bash
#
# maj-grype-vers-gitlab.sh
#
# Exécuté sur la machine X, seule à disposer d'un accès Internet.
# Traite systématiquement les deux composants : le binaire Grype et sa base de
# vulnérabilités. Pour chacun, compare l'amont à ce qui est déjà publié dans
# GitLab ; en cas d'écart, télécharge, vérifie l'empreinte, publie, puis
# supprime la version précédente.
#
# Les capsules ne sortent jamais sur Internet : elles ne lisent que GitLab.
#
# Destination : registre de paquets GitLab, et NON le dépôt Git.
#   Un dépôt Git conserve chaque version dans son historique pour toujours.
#   Une base de plusieurs centaines de Mo renouvelée chaque jour le rendrait
#   impossible à cloner en quelques semaines, et « supprimer » les anciens
#   fichiers ne libérerait rien du tout.
#
# Prévu pour une exécution par cron, toutes les 8 heures :
#
#   7 */8 * * * /opt/vulnscan/maj-grype-vers-gitlab.sh >> /var/log/maj-grype.log 2>&1
#
#   La minute 7 plutôt que 0 : la plupart des tâches planifiées démarrent à
#   l'heure pile, et le proxy est moins sollicité quelques minutes après.
#
# Configuration : /etc/vulnscan/gitlab.env, lu automatiquement s'il existe.
#   GITLAB_URL=https://gitlab.interne
#   GITLAB_PROJET=1234
#   GITLAB_TOKEN=glpat-xxxxx
#   # HTTPS_PROXY=http://proxy.interne:3128
#
#   Ce fichier doit être en 0600. Placer le jeton dans la crontab le rendrait
#   lisible par quiconque peut consulter les tâches planifiées.
#
# Options :
#   --simulation   montre ce qui serait fait, ne pousse rien
#   --forcer       republie même si la version est déjà présente
#
# Codes de retour : 0 tout est à jour, 1 au moins un composant en échec.

set -uo pipefail

CONFIG="${CONFIG:-/etc/vulnscan/gitlab.env}"
# shellcheck disable=SC1090
[ -r "$CONFIG" ] && . "$CONFIG"

GITLAB_URL="${GITLAB_URL:-}"
GITLAB_PROJET="${GITLAB_PROJET:-}"
GITLAB_TOKEN="${GITLAB_TOKEN:-}"

DEPOT_GRYPE="anchore/grype"
ARCH="linux_amd64"
PAQUET_GRYPE="grype"        # paquet générique portant le binaire
PAQUET_BASE="grype-db"      # paquet générique portant la base
TRAVAIL="${TRAVAIL:-/var/tmp/maj-grype}"
VERROU="${VERROU:-/var/tmp/maj-grype.lock}"

SIMULATION=0
FORCER=0

for a in "$@"; do
    case "$a" in
        --simulation) SIMULATION=1 ;;
        --forcer)     FORCER=1 ;;
        -h|--help)    sed -n '3,40p' "$0"; exit 0 ;;
        *) echo "Option inconnue : $a" >&2; exit 2 ;;
    esac
done

# Horodatage systématique : la sortie part dans un journal, et une ligne sans
# date y est inexploitable.
msg()    { printf '%s  %s\n' "$(date '+%F %T')" "$*"; }
info()   { msg "    $*"; }
etape()  { msg "== $*"; }
echec()  { msg "ÉCHEC : $*" >&2; }

for v in GITLAB_URL GITLAB_PROJET GITLAB_TOKEN; do
    if [ -z "${!v}" ]; then
        echec "variable $v non définie (voir $CONFIG)"
        exit 2
    fi
done
command -v python3 >/dev/null || { echec "python3 requis"; exit 2; }

# Un passage qui déborde ne doit pas croiser le suivant : deux exécutions
# simultanées publieraient et supprimeraient les mêmes paquets en même temps.
exec 9>"$VERROU"
if ! flock -n 9; then
    msg "une exécution est déjà en cours, passage ignoré"
    exit 0
fi

API="${GITLAB_URL%/}/api/v4/projects/${GITLAB_PROJET}"
ENTETE=(--header "PRIVATE-TOKEN: ${GITLAB_TOKEN}")

mkdir -p "$TRAVAIL"
trap 'rm -rf "$TRAVAIL"' EXIT

# ---------------------------------------------------------------------------
# Fonctions GitLab
# ---------------------------------------------------------------------------

versions_publiees() {
    local nom="$1"
    curl -fsS --max-time 60 "${ENTETE[@]}" \
         "${API}/packages?package_type=generic&package_name=${nom}&per_page=100" \
    | python3 -I -c '
import json, sys
try:
    paquets = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for p in paquets:
    print(str(p.get("id", "")) + "\t" + str(p.get("version", "")))
'
}

publier() {
    local nom="$1" version="$2" fichier="$3"
    local cible="${API}/packages/generic/${nom}/${version}/$(basename "$fichier")"
    if [ "$SIMULATION" -eq 1 ]; then
        info "SIMULATION : PUT ${cible}"
        return 0
    fi
    curl -fsS --max-time 1800 --upload-file "$fichier" "${ENTETE[@]}" "$cible" >/dev/null \
        || { echec "envoi vers GitLab : $(basename "$fichier")"; return 1; }
    info "publié : ${nom}/${version}/$(basename "$fichier")"
}

# Supprime toutes les versions sauf celle qui vient d'être posée. C'est ce qui
# empêche le registre de grossir indéfiniment, trois fois par jour.
purger_anciennes() {
    local nom="$1" garder="$2" id version
    while IFS=$'\t' read -r id version; do
        [ -n "$id" ] || continue
        [ "$version" = "$garder" ] && continue
        if [ "$SIMULATION" -eq 1 ]; then
            info "SIMULATION : suppression de ${nom}/${version} (id ${id})"
        else
            curl -fsS --max-time 60 --request DELETE "${ENTETE[@]}" \
                 "${API}/packages/${id}" >/dev/null \
                && info "supprimé : ${nom}/${version}" \
                || info "suppression de ${nom}/${version} refusée, à vérifier"
        fi
    done < <(versions_publiees "$nom")
}

# Résout la version amont de Grype. Nécessaire aux deux parties : le binaire
# sert aussi à interroger le catalogue de la base.
version_grype=""
resoudre_version() {
    [ -n "$version_grype" ] && return 0
    if [ -n "${VERSION_GRYPE:-}" ]; then
        version_grype="$VERSION_GRYPE"
        info "version imposée : $version_grype"
        return 0
    fi
    # La redirection de /releases/latest n'est pas soumise au quota de l'API
    # GitHub, souvent atteint derrière un proxy d'entreprise partagé.
    version_grype=$(curl -fsSI --max-time 60 \
        "https://github.com/${DEPOT_GRYPE}/releases/latest" \
        | awk -F'/tag/v' 'tolower($0) ~ /^location:/ {print $2}' | tr -d '\r\n')
    if [ -z "$version_grype" ]; then
        echec "version amont indéterminable. Si le proxy refuse les requêtes
       HEAD, imposer la version : VERSION_GRYPE=0.119.0 dans $CONFIG"
        return 1
    fi
    info "dernière version publiée : $version_grype"
}

# ---------------------------------------------------------------------------
# Partie 1 : binaire Grype
# ---------------------------------------------------------------------------
partie_grype() {
    etape "Binaire Grype"
    resoudre_version || return 1

    local deja
    deja=$(versions_publiees "$PAQUET_GRYPE" \
           | awk -F'\t' -v v="$version_grype" '$2 == v {print $2}')
    if [ -n "$deja" ] && [ "$FORCER" -eq 0 ]; then
        info "GitLab porte déjà $version_grype, rien à faire"
        return 0
    fi

    local url rpm attendu obtenu
    url="https://github.com/${DEPOT_GRYPE}/releases/download/v${version_grype}"
    rpm="grype_${version_grype}_${ARCH}.rpm"

    info "récupération de $rpm"
    curl -fsSL --max-time 900 -o "$TRAVAIL/$rpm" "$url/$rpm" \
        || { echec "paquet introuvable : $rpm"; return 1; }
    curl -fsSL --max-time 120 -o "$TRAVAIL/checksums.txt" \
        "$url/grype_${version_grype}_checksums.txt" \
        || { echec "fichier d'empreintes introuvable"; return 1; }

    # Anchore ne signe pas ses RPM : l'intégrité repose entièrement sur cette
    # vérification. Elle n'est donc pas optionnelle.
    attendu=$(awk -v f="$rpm" '$2 == f || $2 == "*"f {print $1}' "$TRAVAIL/checksums.txt" | head -1)
    [ -n "$attendu" ] || { echec "aucune empreinte publiée pour $rpm"; return 1; }
    obtenu=$(sha256sum "$TRAVAIL/$rpm" | awk '{print $1}')
    if [ "$attendu" != "$obtenu" ]; then
        echec "empreinte non conforme pour $rpm (attendue $attendu, obtenue $obtenu)"
        return 1
    fi
    info "empreinte conforme"

    publier "$PAQUET_GRYPE" "$version_grype" "$TRAVAIL/$rpm" || return 1
    # Le fichier d'empreintes est publié avec le paquet : la capsule pourra
    # revérifier son téléchargement sans sortir sur Internet.
    publier "$PAQUET_GRYPE" "$version_grype" "$TRAVAIL/checksums.txt" || return 1
    purger_anciennes "$PAQUET_GRYPE" "$version_grype"
}

# ---------------------------------------------------------------------------
# Partie 2 : base de vulnérabilités
# ---------------------------------------------------------------------------
version_base=""
partie_base() {
    etape "Base de vulnérabilités"
    resoudre_version || return 1

    # Le catalogue est interrogé avec le binaire Grype lui-même plutôt qu'avec
    # une URL codée en dur : le format de distribution a déjà changé entre
    # versions de schéma. Rien n'est installé sur la machine X.
    local tgz
    tgz="grype_${version_grype}_${ARCH}.tar.gz"
    if [ ! -x "$TRAVAIL/grype" ]; then
        curl -fsSL --max-time 900 -o "$TRAVAIL/$tgz" \
            "https://github.com/${DEPOT_GRYPE}/releases/download/v${version_grype}/$tgz" \
            || { echec "archive du binaire introuvable"; return 1; }
        tar -xzf "$TRAVAIL/$tgz" -C "$TRAVAIL" grype \
            || { echec "extraction du binaire impossible"; return 1; }
        chmod +x "$TRAVAIL/grype"
    fi

    info "interrogation du catalogue amont"
    if ! "$TRAVAIL/grype" db list -o json > "$TRAVAIL/catalogue.json" 2>"$TRAVAIL/catalogue.err"; then
        echec "catalogue inaccessible : $(head -2 "$TRAVAIL/catalogue.err" | tr '\n' ' ')"
        return 1
    fi

    # Le format de ce catalogue a évolué. On cherche l'URL et l'empreinte par
    # leur présence plutôt qu'à une position fixe, et on échoue bruyamment si
    # rien n'est trouvé, en conservant le fichier pour analyse.
    local lu
    lu=$(python3 -I -c '
import json, sys

def parcourir(n):
    if isinstance(n, dict):
        url = n.get("url") or n.get("URL")
        somme = n.get("checksum") or n.get("Checksum") or n.get("digest")
        if url and somme:
            yield str(url), str(somme), str(n.get("built") or n.get("Built")
                                             or n.get("date") or "inconnue")
        for v in n.values():
            yield from parcourir(v)
    elif isinstance(n, list):
        for v in n:
            yield from parcourir(v)

trouves = list(parcourir(json.load(open(sys.argv[1]))))
if not trouves:
    sys.exit(1)
print("\t".join(trouves[0]))
' "$TRAVAIL/catalogue.json")
    if [ -z "$lu" ]; then
        cp "$TRAVAIL/catalogue.json" /var/tmp/catalogue-grype-non-reconnu.json 2>/dev/null
        echec "format de catalogue non reconnu.
       Copie conservée dans /var/tmp/catalogue-grype-non-reconnu.json"
        return 1
    fi

    local url_base somme_base date_base fichier attendu obtenu deja
    url_base=$(printf '%s' "$lu" | cut -f1)
    somme_base=$(printf '%s' "$lu" | cut -f2)
    date_base=$(printf '%s' "$lu" | cut -f3)
    fichier=$(basename "${url_base%%\?*}")

    # La version du paquet porte la date de construction de la base : c'est
    # elle qui figurera dans la traçabilité du rapport.
    version_base=$(printf '%s' "$date_base" | tr -cd '0-9' | cut -c1-8)
    [ -n "$version_base" ] || version_base=$(date +%Y%m%d)
    info "base amont construite le $date_base (version $version_base)"

    deja=$(versions_publiees "$PAQUET_BASE" \
           | awk -F'\t' -v v="$version_base" '$2 == v {print $2}')
    if [ -n "$deja" ] && [ "$FORCER" -eq 0 ]; then
        info "GitLab porte déjà cette base, rien à faire"
        return 0
    fi

    info "téléchargement de $fichier"
    curl -fsSL --max-time 1800 -o "$TRAVAIL/$fichier" "$url_base" \
        || { echec "téléchargement de la base"; return 1; }

    attendu=${somme_base#sha256:}
    obtenu=$(sha256sum "$TRAVAIL/$fichier" | awk '{print $1}')
    if [ "$attendu" != "$obtenu" ]; then
        echec "empreinte de la base non conforme (attendue $attendu, obtenue $obtenu)"
        return 1
    fi
    info "empreinte conforme"

    # L'empreinte accompagne l'archive : la capsule la passera à
    # `grype db import` pour revérifier avant installation.
    printf '%s  %s\n' "$obtenu" "$fichier" > "$TRAVAIL/base.sha256"

    publier "$PAQUET_BASE" "$version_base" "$TRAVAIL/$fichier" || return 1
    publier "$PAQUET_BASE" "$version_base" "$TRAVAIL/base.sha256" || return 1
    purger_anciennes "$PAQUET_BASE" "$version_base"
}

# ---------------------------------------------------------------------------
# Enchaînement
# ---------------------------------------------------------------------------
msg "Démarrage sur $(hostname -s)"

# Les deux parties sont tentées indépendamment : un amont indisponible pour
# l'une ne doit pas empêcher l'autre d'être mise à jour.
etat_grype=0
etat_base=0
partie_grype || etat_grype=1
partie_base  || etat_base=1

etape "Bilan"
info "binaire Grype : $([ $etat_grype -eq 0 ] && echo "à jour (${version_grype:-?})" || echo 'ÉCHEC')"
info "base          : $([ $etat_base  -eq 0 ] && echo "à jour (${version_base:-?})"  || echo 'ÉCHEC')"

[ $((etat_grype + etat_base)) -eq 0 ] || exit 1
