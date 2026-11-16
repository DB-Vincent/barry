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

# Bump the single source of truth: the [workspace.package] version in the root
# manifest. Every workspace crate inherits it with `version.workspace = true`.
#
# Do not rewrite every other Cargo.toml: `fuzz/` and `vendor/tree-sitter-bash/`
# carry versions of their own, and the vendored grammar's has to keep matching
# the `[patch.crates-io]` pin. The 0.1.1 release bumped it to 0.1.1, which made
# cargo drop the patch (warning: "patch ... was not used in the crate graph")
# and silently reintroduce the parser crash it exists to fix.
sed -i "/^\[workspace\.package\]/,/^\[/ s/^version = .*/version = \"${NEW_VERSION_NO_V}\"/" Cargo.toml

if ! grep -qx "version = \"${NEW_VERSION_NO_V}\"" Cargo.toml; then
    echo "error: [workspace.package] version was not bumped in Cargo.toml" >&2
    exit 1
fi

# Keep Cargo.lock in step with the manifests, so the tagged commit does not
# carry a lock file that the next cargo invocation has to rewrite.
cargo metadata --format-version 1 >/dev/null

git add -A
if ! git diff --cached --quiet; then
    git commit -m "chore(release): release $NEW_VERSION_NO_V"
    git tag "$NEW_VERSION"
    git push origin HEAD --tags
    # Expose the tag so the workflow's build job knows a release was made.
    # A GITHUB_TOKEN push does not trigger tag-triggered workflows.
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        echo "tag=${NEW_VERSION}" >> "$GITHUB_OUTPUT"
    fi
else
    echo "no-release: version unchanged after bump"
fi
