#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# 1. Ensure we are inside a Git repository
# ------------------------------------------------------------
if ! REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
  echo "Error: Not inside a Git repository."
  exit 1
fi

REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
HEAD_BRANCH=$(git rev-parse --abbrev-ref HEAD)

OUTDIR="$REPO_ROOT/.gh-pr-export/copilot"
mkdir -p "$OUTDIR"

echo "Repo root : $REPO_ROOT"
echo "Head branch: $HEAD_BRANCH"
echo "Output dir : $OUTDIR"
echo ""

# ------------------------------------------------------------
# 2. Get open PRs for current head branch
# ------------------------------------------------------------
PRS_JSON=$(gh pr list \
  --state open \
  --head "$HEAD_BRANCH" \
  --json number,title,url \
  -q '.')

COUNT=$(printf '%s' "$PRS_JSON" | jq 'length')

if [ "$COUNT" -eq 0 ]; then
  echo "No open PR found for head=$HEAD_BRANCH"
  exit 0
fi

echo "Found $COUNT open PR(s)"
echo ""

# ------------------------------------------------------------
# 3. Loop through PRs
# ------------------------------------------------------------
printf '%s' "$PRS_JSON" | jq -r '.[].number' | while read -r NUMBER; do

  FILE="$OUTDIR/pr-${NUMBER}.copilot.json"
  echo "Processing PR #$NUMBER"

  COMMENTS=$(gh api "repos/$REPO/pulls/$NUMBER/comments" --paginate)
  REVIEWS=$(gh api "repos/$REPO/pulls/$NUMBER/reviews" --paginate)

  # ----------------------------------------------------------
  # 4. Extract Copilot-only comments
  # ----------------------------------------------------------
  JSON_OUTPUT=$(jq -n \
    --arg repo "$REPO" \
    --arg head "$HEAD_BRANCH" \
    --argjson comments "$COMMENTS" \
    --argjson reviews "$REVIEWS" \
    '
    def is_copilot(login):
      (login | ascii_downcase)
      | test("copilot|copilot-pull-request-reviewer|github-copilot|\\[bot\\]$|bot$");

    {
      meta: {
        repo: $repo,
        head: $head
      },

      inline_comments:
        ($comments
          | map(select(is_copilot(.user.login)))
          | map({
              file: .path,
              line: (.line // .original_line // null),
              body: .body,
              url: .html_url
            })
        ),

      reviews:
        ($reviews
          | map(select(is_copilot(.user.login)))
          | map({
              state: .state,
              body: .body,
              url: .html_url
            })
        )
    }
    ')

  # ----------------------------------------------------------
  # 5. Only write file if Copilot left something
  # ----------------------------------------------------------
  INLINE_COUNT=$(printf '%s' "$JSON_OUTPUT" | jq '.inline_comments | length')
  REVIEW_COUNT=$(printf '%s' "$JSON_OUTPUT" | jq '.reviews | length')

  if [ "$INLINE_COUNT" -eq 0 ] && [ "$REVIEW_COUNT" -eq 0 ]; then
    echo "  No Copilot comments found. Skipping file."
    continue
  fi

  printf '%s\n' "$JSON_OUTPUT" > "$FILE"

  echo "  Saved -> $FILE"
  echo ""

done

echo "Done."
