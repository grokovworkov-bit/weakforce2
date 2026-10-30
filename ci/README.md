# CI workflow

`github-actions-build.yml.disabled` is the GitHub Actions workflow for building TweakForce.

It is stored here (not under `.github/workflows/`) because it was pushed with a Personal
Access Token that lacks the `workflow` scope. To enable CI:

1. Move it back:
   `mkdir -p .github/workflows && git mv ci/github-actions-build.yml.disabled .github/workflows/build.yml`
2. Commit and push using a token that has the `workflow` scope (or via the GitHub web UI).
