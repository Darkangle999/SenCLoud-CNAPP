#!/bin/bash
# Pre-commit hook to block hardcoded secrets

# Get list of staged files
staged_files=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$staged_files" ]; then
    exit 0
fi

has_secrets=0

for file in $staged_files; then
    # Skip if file is deleted or is this script itself
    if [ ! -f "$file" ] || [ "$file" = "scripts/check_secrets.sh" ]; then
        continue
    fi

    # Grep for secrets in the staged files
    if grep -E -i -q "AKIA[A-Z0-9]{16}|bolt://|password=" "$file"; then
        echo "ERROR: Hardcoded secret detected in $file!"
        has_secrets=1
    fi
done

if [ $has_secrets -eq 1 ]; then
    echo "Commit blocked. Please remove the secrets from the codebase."
    exit 1
fi

exit 0
