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
# The npm registry occasionally returns 404 on the publish PUT response even
# though the package write succeeded server-side (CDN/replication false
# negative). On non-zero exit, verify whether the version landed before
# failing.
set -uo pipefail

VERSION="${1:?usage: release-publish.sh <version>}"
PKG="@theqrl/wallet.js"

echo "Publishing ${PKG}@${VERSION} to npm (trusted publishing)"
npm publish
code=$?

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
