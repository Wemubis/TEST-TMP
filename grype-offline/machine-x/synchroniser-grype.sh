#!/usr/bin/env bash
# Machine X uniquement. Bash + curl + jq + git + tar + sha256sum + flock.
# Un commit publie ensemble le RPM, la DB et leurs métadonnées validées.
set -euo pipefail
umask 077

: "${GITLAB_DEPOT:?Définir GITLAB_DEPOT (URL SSH du dépôt des rôles)}"
GITLAB_BRANCHE=${GITLAB_BRANCHE:-main}
SYNC_CACHE=${SYNC_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/grype-sync}
GIT_AUTHOR_NAME=${GIT_AUTHOR_NAME:-Grype synchronisation}
GIT_AUTHOR_EMAIL=${GIT_AUTHOR_EMAIL:-grype-sync@localhost}
export GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GIT_TERMINAL_PROMPT=0
export GIT_SSH_COMMAND='ssh -o BatchMode=yes'
export GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false

for outil in curl jq git tar sha256sum flock mktemp awk cmp grype find sort gzip xargs; do
    command -v "$outil" >/dev/null || { echo "Outil absent : $outil" >&2; exit 1; }
done
case "$(uname -m)" in
    x86_64) arch=linux_amd64 ;;
    aarch64) arch=linux_arm64 ;;
    *) echo 'Architecture non prise en charge' >&2; exit 1 ;;
esac
mkdir -p "$SYNC_CACHE"
SYNC_CACHE=$(cd "$SYNC_CACHE" && pwd)
exec 9>"$SYNC_CACHE/synchronisation.lock"
flock -n 9 || { echo 'Synchronisation déjà en cours' >&2; exit 1; }
travail=$(mktemp -d "$SYNC_CACHE/travail.XXXXXX")
trap 'rm -rf -- "$travail"' EXIT
cd "$travail"

telecharger() {
    curl --fail --silent --show-error --location --retry 3 \
      --connect-timeout 30 --max-time 1800 --proto '=https' --proto-redir '=https' \
      "$1" --output "$2"
}
verifier() {
    [[ "$2" =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'SHA-256 invalide' >&2; return 1; }
    printf '%s  %s\n' "$2" "$1" | sha256sum --check --status
}
empreinte() {
    awk -v f="$1" '$2 == f || $2 == "*"f {print $1}' checksums.txt
}

# 1. Dernière version officielle ; petits fichiers de métadonnées seulement.
telecharger https://api.github.com/repos/anchore/grype/releases/latest release.json
version=$(jq -er '.tag_name | select(test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")) | ltrimstr("v")' release.json)
url="https://github.com/anchore/grype/releases/download/v${version}"
rpm="grype_${version}_${arch}.rpm"
telecharger "$url/grype_${version}_checksums.txt" checksums.txt
rpm_sha=$(empreinte "$rpm")
[[ "$rpm_sha" =~ ^[a-fA-F0-9]{64}$ ]] || {
    echo 'Empreinte officielle RPM absente ou ambiguë' >&2; exit 1;
}

# Utiliser exclusivement le Grype déjà installé sur X.
version_x=$(grype version -o json | jq -er '.version | ltrimstr("v")')
[[ "$version_x" == "$version" ]] || {
    echo "Mettre à jour Grype sur X : installé $version_x, attendu $version. Rien publié." >&2
    exit 1
}
# Cache persistant réservé à ce script : aucun scan concurrent sur ce cache.
export GRYPE_DB_CACHE_DIR="$SYNC_CACHE/db"
mkdir -p "$GRYPE_DB_CACHE_DIR"
printf 'db:\n  auto-update: false\ncheck-for-app-update: false\n' > grype.yaml
grype -c grype.yaml db update
grype -c grype.yaml db status
# L'identité repose sur les fichiers DB, pas sur les dates de contrôle du cache.
(
    cd "$GRYPE_DB_CACHE_DIR"
    find . -type f -name '*.db' -print0 | sort -z | xargs -0 -r sha256sum
) > contenu.sha256
[[ -s contenu.sha256 ]] || { echo 'Aucun fichier DB trouvé' >&2; exit 1; }
db_contenu=$(sha256sum contenu.sha256 | awk '{print $1}')

# 3. État publié dans GitLab. Clone privé, aucun checkout utilisateur modifié.
git clone --quiet --depth 1 --single-branch --branch "$GITLAB_BRANCHE" -- "$GITLAB_DEPOT" depot
cible="$travail/depot/roles/maj_grype_capsule/files/current"
mkdir nouveau
rpm_change=true
db_change=true
if [[ -f "$cible/grype.rpm" ]] && verifier "$cible/grype.rpm" "$rpm_sha"; then
    rpm_change=false
    cp "$cible/grype.rpm" nouveau/grype.rpm
else
    telecharger "$url/$rpm" nouveau/grype.rpm
    verifier nouveau/grype.rpm "$rpm_sha"
fi
if [[ -f "$cible/manifest.json" && -f "$cible/db-cache.tar.gz" ]] &&
   [[ "$(jq -r '.db_content_sha256 // empty' "$cible/manifest.json")" == "$db_contenu" ]] &&
   verifier "$cible/db-cache.tar.gz" "$(jq -r '.db_sha256' "$cible/manifest.json")"; then
    db_change=false
    cp "$cible/db-cache.tar.gz" nouveau/db-cache.tar.gz
else
    # Copie du cache entier, avec son arborescence de schémas. Ce n'est pas
    # une archive officielle destinée à `grype db import`.
    tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        -C "$GRYPE_DB_CACHE_DIR" -cf - . | gzip -n > nouveau/db-cache.tar.gz
fi
db_sha=$(sha256sum nouveau/db-cache.tar.gz | awk '{print $1}')
jq -n --arg version "$version" --arg arch "$arch" \
    --arg rpm_sha256 "$rpm_sha" --arg db_sha256 "$db_sha" \
    --arg db_content_sha256 "$db_contenu" --arg rpm_url "$url/$rpm" \
    '{version:$version,arch:$arch,rpm_sha256:$rpm_sha256,db_sha256:$db_sha256,
      db_content_sha256:$db_content_sha256,db_format:"cache-v1",rpm_url:$rpm_url}' \
    > nouveau/manifest.json

if ! $rpm_change && ! $db_change && cmp -s nouveau/manifest.json "$cible/manifest.json"; then
    echo "Déjà à jour : Grype $version et DB. Aucun commit."
    exit 0
fi

# Valider également la restauration du cache avant publication.
mkdir db-test
tar -xzf nouveau/db-cache.tar.gz -C db-test
GRYPE_DB_CACHE_DIR="$travail/db-test" grype -c grype.yaml db status

# 5. Remplacement limité au répertoire de distribution, puis un seul commit.
# Les rôles et templates du dépôt ne sont jamais supprimés.
mkdir -p "$(dirname "$cible")"
rm -rf -- "$cible"
mv nouveau "$cible"
git -C depot add --all -- roles/maj_grype_capsule/files/current
if git -C depot diff --cached --quiet; then
    echo 'Aucune modification à publier.'
    exit 0
fi
git -C depot commit --quiet -m "Grype $version : actualisation RPM et DB"
# Pas de force-push : si la branche a avancé, arrêter et relancer le script.
git -C depot push origin "HEAD:refs/heads/$GITLAB_BRANCHE"
echo "Publié : Grype $version ; DB $db_contenu (RPM modifié : $rpm_change ; DB modifiée : $db_change)."
