#!/usr/bin/env bash
set -euo pipefail

cargo check -p cipherrun-worker --all-targets --locked

# The worker depends on the matching released cipherrun version. The root
# package is published immediately before this crate in the release workflow;
# local checks run before that registry publication exists.
if cargo package -p cipherrun-worker --locked --allow-dirty 2>worker-package.err; then
    rm -f worker-package.err
else
    if grep -q "candidate versions found" worker-package.err; then
        echo "worker package smoke deferred until cipherrun ${CARGO_PKG_VERSION:-0.4.0} is published"
        rm -f worker-package.err
    else
        cat worker-package.err >&2
        rm -f worker-package.err
        exit 1
    fi
fi
