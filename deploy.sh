#!/bin/bash
# deploy.sh — Release a new version of Yoro Inventory PRO to Railway
# Usage:
#   ./deploy.sh              → auto-version as v2026-04-27
#   ./deploy.sh v2.1         → custom version label
#   ./deploy.sh v2.1 "Added batch invoicing"  → with a note

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSIONS_DIR="$PROJECT_DIR/versions"
RAILWAY_CLI="${RAILWAY_CLI_PATH:-$(which railway 2>/dev/null || echo "$HOME/.local/bin/railway")}"

# --- Version label ---
if [ -n "$1" ]; then
    VERSION="$1"
else
    VERSION="v$(date +%Y-%m-%d)"
fi
NOTE="${2:-}"

echo ""
echo "Yoro Inventory PRO — Deploy: $VERSION"
echo "======================================="

# --- Snapshot key files locally ---
SNAPSHOT_DIR="$VERSIONS_DIR/$VERSION"
if [ -d "$SNAPSHOT_DIR" ]; then
    echo "Version $VERSION snapshot already exists — overwriting."
fi
mkdir -p "$SNAPSHOT_DIR"
cp "$PROJECT_DIR/index.html"      "$SNAPSHOT_DIR/"
cp "$PROJECT_DIR/proxy_server.py" "$SNAPSHOT_DIR/"
echo "Version:   $VERSION"                    > "$SNAPSHOT_DIR/VERSION.txt"
echo "Date:      $(date)"                    >> "$SNAPSHOT_DIR/VERSION.txt"
echo "Note:      ${NOTE:-no note}"           >> "$SNAPSHOT_DIR/VERSION.txt"
echo "  Snapshot saved to versions/$VERSION/"

# --- Git commit + tag ---
cd "$PROJECT_DIR"
git add index.html proxy_server.py railway.toml nixpacks.toml Procfile .gitignore 2>/dev/null || true

COMMIT_MSG="Release $VERSION"
[ -n "$NOTE" ] && COMMIT_MSG="$COMMIT_MSG — $NOTE"

if git diff --cached --quiet; then
    echo "  No file changes to commit."
else
    git commit -m "$COMMIT_MSG"
    echo "  Git commit created."
fi

if git tag "$VERSION" 2>/dev/null; then
    echo "  Git tag: $VERSION"
else
    echo "  Git tag $VERSION already exists — skipping."
fi

# --- Deploy to Railway ---
echo "  Deploying to Railway..."
"$RAILWAY_CLI" up --detach --service "yoro-inventory"
echo "  Railway deploy triggered."

# --- Prune local snapshots older than 12 months ---
PRUNED=0
while IFS= read -r -d '' old_dir; do
    rm -rf "$old_dir"
    PRUNED=$((PRUNED + 1))
done < <(find "$VERSIONS_DIR" -maxdepth 1 -mindepth 1 -type d -mtime +365 -print0 2>/dev/null)
[ "$PRUNED" -gt 0 ] && echo "  Pruned $PRUNED snapshot(s) older than 12 months."

echo ""
echo "Done."
echo "  Version:  $VERSION"
echo "  Local:    $VERSIONS_DIR/$VERSION/"
echo "  Live:     https://yoro-inventory-production.up.railway.app"
echo ""
