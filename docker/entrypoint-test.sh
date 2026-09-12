#!/bin/bash -l
set -e
# shellcheck disable=SC1091
source /.venv/bin/activate
if [ "$#" -eq 0 ]; then
  # Kill cache, pytest complains about it if running local and docker tests in mapped volume
  find tests  -type d -name '__pycache__' -print0 | xargs -0 rm -rf {}
  # Make sure the service itself is installed
  uv sync --frozen
  # Make sure pre-commit checks were not missed because reasons. Via the init script because
  # .git is not in the image and prek needs a repository.
  docker/pre_commit_init.sh
  # Then run the tests
  pytest --junitxml=pytest.xml tests/
  # If prek does not run these, enable them
  # mypy src tests
  # bandit --skip=B101 -r src
else
  exec "$@"
fi
