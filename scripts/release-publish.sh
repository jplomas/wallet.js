#!/usr/bin/env bash
# npm publish hook for semantic-release (@semantic-release/exec publishCmd).
#
# Runs inside semantic-release's publish phase, which executes plugins in
# .releaserc.json order — i.e. BEFORE @semantic-release/github creates the
# GitHub release. A failed npm publish therefore aborts the release before
# any GitHub release exists, so a GitHub release is a reliable signal that
# the version is on npm. (Previously npm publish ran as a separate workflow
# step after semantic-release finished; a publish failure orphaned the tag
# AND the GitHub release — this is how v6.2.0 ended up tagged+released but
# never on npm. The git tag itself is still pushed by semantic-release core
# before the publish phase; if publish fails, see RELEASE.md "Recovering an
# orphaned release".)
#
# Publish-the-tarball: the package is packed exactly once (into
# .release/tarballs/) and that file is what `npm publish` uploads. The
# workflow hands the same file to the SBOM / attestation / SLSA jobs, so
# supply-chain artifacts describe the published bytes by construction —
# never a rebuild of a floating ref — and the workflow's post-publish
# integrity gate re-checks the registry's advertised sha-512 against it.
#
# The npm registry occasionally returns 404 on the publish PUT response even
# though the package write succeeded server-side (CDN/replication false
# negative). On non-zero exit, verify whether the version landed before
# failing.
set -euo pipefail

VERSION="${1:?usage: release-publish.sh <version>}"
PKG="@theqrl/wallet.js"
TARBALL_DIR=".release/tarballs"

# Replicates the prepublishOnly hook a directory publish would have run:
# build with the released version already stamped into package.json.
# (dist/ output is version-independent and preflight's dist-clean check
# pins it to the committed tree, but the semantics stay identical on
# purpose — a manual directory publish and this script must not diverge.)
npm run build

mkdir -p "${TARBALL_DIR}"
# `npm pack` prints the created filename as its last stdout line.
TARBALL_NAME="$(npm pack --pack-destination "${TARBALL_DIR}" | tail -n 1)"
TARBALL="${TARBALL_DIR}/${TARBALL_NAME}"

# Tripwire: the packed artifact must carry the version being released.
case "${TARBALL_NAME}" in
  *"-${VERSION}.tgz") ;;
  *)
    echo "packed ${TARBALL_NAME} does not match release version ${VERSION} — aborting before publish" >&2
    exit 1
    ;;
esac

# Tripwire: declared entrypoints must be inside the tarball, and obvious
# junk must not (cf. the qrypto.js inspect-packages release tripwire).
for required in \
  package/package.json \
  package/dist/mjs/wallet.js \
  package/dist/cjs/wallet.js \
  package/types/index.d.ts; do
  if ! tar -tzf "${TARBALL}" "${required}" > /dev/null 2>&1; then
    echo "tarball is missing ${required} — aborting before publish" >&2
    exit 1
  fi
done
if tar -tzf "${TARBALL}" | grep -E 'node_modules/|^package/\.release/|\.tgz$'; then
  echo "tarball contains forbidden paths (above) — aborting before publish" >&2
  exit 1
fi

echo "Publishing ${PKG}@${VERSION} to npm (trusted publishing, ${TARBALL})"
code=0
npm publish "${TARBALL}" || code=$?

if [ "${code}" -ne 0 ]; then
  echo "npm publish exited ${code} — checking whether ${PKG}@${VERSION} actually landed"
  sleep 15
  published="$(npm view "${PKG}@${VERSION}" version 2>/dev/null || true)"
  if [ "${published}" = "${VERSION}" ]; then
    echo "${PKG}@${VERSION} is on the registry — treating as success"
    exit 0
  fi
  echo "${PKG}@${VERSION} is NOT on the registry — failing before the GitHub release is created"
  exit "${code}"
fi

echo "${PKG}@${VERSION} published"
