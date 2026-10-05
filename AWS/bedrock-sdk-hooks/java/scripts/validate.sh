#!/usr/bin/env bash
# Validation for the Prisma AIRS Bedrock ExecutionInterceptor -- real scans, no mocks.
#
#   scripts/validate.sh             # core checks, no AWS account needed
#   scripts/validate.sh --bedrock   # + a real Bedrock round trip (needs AWS creds)
#
# Needs PRISMA_AIRS_API_KEY and PRISMA_AIRS_PROFILE_NAME in the environment
# (see examples/env.example), a JDK 17+, and Maven.
set -euo pipefail
cd "$(dirname "$0")/.."

# Locate a JDK for Maven. Homebrew's openjdk is keg-only (not linked into PATH),
# so probe its keg directly when JAVA_HOME is not already set.
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME}/bin/java" ]; then
    if [ -x /opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java ]; then
        export JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home
    elif [ -x /opt/homebrew/opt/openjdk/bin/java ]; then
        export JAVA_HOME=/opt/homebrew/opt/openjdk
    elif command -v /usr/libexec/java_home >/dev/null 2>&1 && /usr/libexec/java_home >/dev/null 2>&1; then
        JAVA_HOME="$(/usr/libexec/java_home)"
        export JAVA_HOME
    fi
fi
if [ -z "${JAVA_HOME:-}" ] && ! command -v java >/dev/null 2>&1; then
    echo "ERROR: no JDK found -- install one (e.g. 'brew install openjdk') or set JAVA_HOME" >&2
    exit 2
fi

exec mvn -q compile exec:java -Dexec.args="$*"
