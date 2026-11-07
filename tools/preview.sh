#!/usr/bin/env bash
# Live preview at http://127.0.0.1:4000 using Docker (no local Ruby needed).
# Add --drafts to also render files in _drafts/.
cd "$(dirname "$0")/.."
docker volume create chirpy-gems >/dev/null
exec docker run --rm -it -p 4000:4000 -p 35729:35729 \
  -u "$(id -u):$(id -g)" -e HOME=/tmp -e BUNDLE_PATH=/gems \
  -v chirpy-gems:/gems -v "$PWD":/srv -w /srv ruby:3.3 \
  bash -c "git config --global --add safe.directory /srv; bundle install -j4 --quiet && bundle exec jekyll serve -H 0.0.0.0 -l $*"
