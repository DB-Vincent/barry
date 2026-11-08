#!/usr/bin/env bash
# Auto-bump semver based on conventional commits since the last tag.
# feat      -> minor
# fix       -> patch
# BREAKING CHANGE -> major
# docs/chore/etc -> no bump (no release)
set -euo pipefail

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

git fetch --tags --force >/dev/null 2>&1 || true

LATEST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || echo 'v0.0.0')"
CURRENT_VERSION="${LATEST_TAG#v}"

if [ "$LATEST_TAG" = "v0.0.0" ]; then
    COMMIT_RANGE=""
else
    COMMIT_RANGE="${LATEST_TAG}..HEAD"
fi

COMMITS="$(git log --pretty=format:'%s' ${COMMIT_RANGE})"

MAJOR=0; MINOR=0; PATCH=0
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

BUMP="none"
while IFS= read -r line; do
    case "$line" in
        feat*) BUMP="minor" ;;
        fix*)
            [ "$BUMP" != "minor" ] && BUMP="patch"
            ;;
        *"BREAKING CHANGE*"|*"breaking change"*)
            BUMP="major"
            ;;
    esac
done <<< "$COMMITS"

if [ "$BUMP" = "none" ]; then
    echo "no-release: no feat/fix/breaking-commit since $LATEST_TAG"
    exit 0
fi

case "$BUMP" in
    major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
    minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
    patch) PATCH=$((PATCH + 1)) ;;
esac

NEW_VERSION_NO_V="${MAJOR}.${MINOR}.${PATCH}"
NEW_VERSION="v${NEW_VERSION_NO_V}"

echo "release: $CURRENT_VERSION -> $NEW_VERSION_NO_V ($BUMP)"

# Bump every Cargo.toml that carries a version field.
CHANGED=0
while IFS= read -r -d '' f; do
    sed -i "s/^version = .*/version = \"${NEW_VERSION_NO_V}\"/" "$f"
    CHANGED=1
done < <(grep -rlZ '^version = ' --include='Cargo.toml' . || true)

if [ "$CHANGED" = "0" ]; then
    echo "no-release: no Cargo.toml version fields to bump"
    exit 0
fi

git add -A
if ! git diff --cached --quiet; then
    git commit -m "chore(release): release $NEW_VERSION_NO_V"
    git tag "$NEW_VERSION"
    git push origin HEAD --tags
else
    echo "no-release: version unchanged after bump"
fi
