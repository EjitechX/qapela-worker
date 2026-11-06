#!/data/data/com.termux/files/usr/bin/bash
# Qapela one-command redeploy from Termux.
# Usage: bash deploy.sh "commit message"
set -e
cd "$(dirname "$0")"
MSG="${1:-Update Qapela (PWA)}"
[ -d .git ] || { echo "This folder is not a git clone. See the steps: clone EjitechX/qapela-worker first."; exit 1; }
git add -A
git commit -m "$MSG" || echo "Nothing new to commit"
git push origin main
echo "Done. GitHub Pages updates in ~1 min; Cloudflare redeploys worker.js automatically."
