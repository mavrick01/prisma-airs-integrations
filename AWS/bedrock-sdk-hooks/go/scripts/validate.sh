#!/bin/sh
# Runs the validation suite from anywhere: scripts/validate.sh [--bedrock]
cd "$(dirname "$0")/.." && exec go run ./scripts/validate "$@"
