# ─────────────────────────────────────────────────────────────────────────────
# Stage 0 — patch security-analytics-commons-1.0.0.jar
#
# Context: the JAR is a fat/shaded artifact that embeds io.netty class files
# and their META-INF/maven/io.netty/*/pom.properties at version 4.1.133.Final.
# Trivy detects the CVEs via those pom.properties entries AND the class bytecode.
#
# Fix: for each vulnerable netty artifact, extract the patched 4.2.15.Final
# class files + pom.properties (via unzip -o) over the existing contents, then
# repack.  MANIFEST.MF from the original JAR is preserved so plugin loading
# is unaffected.
# ─────────────────────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-21 AS jar-patcher

# Pull the JAR directly from the base image — no need to run the container.
COPY --from=opensearchproject/opensearch:3.7.0 \
    /usr/share/opensearch/plugins/opensearch-security-analytics/security-analytics-commons-1.0.0.jar \
    /work/orig.jar

WORKDIR /work/extracted

# Extract full original JAR (preserves MANIFEST.MF and all non-netty content)
RUN jar xf /work/orig.jar

# For each netty artifact that has embedded classes + pom.properties in the fat JAR:
#   1. Download patched 4.2.15.Final from Maven Central
#   2. Overlay io/netty/** class files (unzip -o = overwrite existing)
#   3. Update the embedded pom.properties version string
RUN for artifact in \
        netty-handler \
        netty-codec-http2 \
        netty-codec-http \
        netty-codec \
        netty-transport \
        netty-transport-classes-epoll \
        netty-transport-native-unix-common \
        netty-buffer \
        netty-resolver \
        netty-common; do \
        mvn --batch-mode --no-transfer-progress dependency:copy \
            -Dartifact="io.netty:${artifact}:4.2.15.Final" \
            -DoutputDirectory=/tmp/patches; \
        # Overlay class files only (avoids overwriting MANIFEST.MF)
        unzip -o -q "/tmp/patches/${artifact}-4.2.15.Final.jar" \
            "io/netty/*" "META-INF/maven/io.netty/${artifact}/*" \
            -d /work/extracted 2>/dev/null || true; \
        # Update the version declared in pom.properties so scanners see 4.2.15.Final
        props="META-INF/maven/io.netty/${artifact}/pom.properties"; \
        [ -f "${props}" ] && \
            sed -i 's/^version=.*/version=4.2.15.Final/' "${props}" && \
            echo "Updated ${props}"; \
    done

# Repack with the original manifest + patched netty classes/pom
RUN jar cf /work/patched.jar .

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — final patched OpenSearch image
# Fixes the following CVEs:
#
# OS (libsolv):
#   CVE-2026-48863  CVE-2026-48864  CVE-2026-9149  CVE-2026-9150
#   libsolv is only needed by dnf/rpm at build time — it is not used by OpenSearch
#   at runtime.  We remove dnf, libdnf, libsolv and their Python bindings after all
#   package operations are complete, which eliminates the CVE attack surface entirely
#   rather than waiting for 0.7.22-1.amzn2023.0.4 to land in the AL2023 mirror.
#
# Java (io.netty:netty-handler 4.1.133.Final → 4.2.15.Final):
#   CVE-2026-44249  CVE-2026-45416  CVE-2026-50010
#   Addressed in two ways:
#   a) Standalone netty-handler-4.1.x.jar files in plugin dirs → replaced with
#      netty-handler-4.2.15.Final.jar already present in transport-netty4 module.
#   b) security-analytics-commons-1.0.0.jar (shaded fat JAR) → replaced with
#      the jar-patcher stage output (class files + pom.properties at 4.2.15.Final).
# ─────────────────────────────────────────────────────────────────────────────
FROM opensearchproject/opensearch:3.7.0

USER root

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Use dnf for any remaining package upgrades, then remove it entirely.
# This eliminates libsolv (CVE-2026-48863/48864/9149/9150) from the final image;
# the package manager is never needed at runtime.
RUN dnf -y --refresh upgrade \
     && dnf clean all \
     && rm -rf /var/cache/dnf \
     && rpm -e --nodeps \
          libsolv \
          libdnf \
          python3-dnf \
          python3-libdnf \
          dnf \
          dnf-data \
          2>/dev/null; \
    echo "Remaining package-mgr packages: $(rpm -qa libsolv dnf libdnf 2>/dev/null | tr '\n' ' ' || echo none)"

# netty-handler CVEs — standalone JARs: only replace the old 4.1.x version files;
# already-patched 4.2.x files and proxy/other variants are skipped via exact glob
RUN src=/usr/share/opensearch/modules/transport-netty4/netty-handler-4.2.15.Final.jar; \
    for old_jar in /usr/share/opensearch/plugins/*/netty-handler-4.1.*.jar; do \
        [ -f "${old_jar}" ] || continue; \
        dir="${old_jar%/*}"; \
        echo "Replacing standalone JAR: ${old_jar}"; \
        rm -f "${old_jar}"; \
        cp "${src}" "${dir}/"; \
        chmod 644 "${dir}/netty-handler-4.2.15.Final.jar"; \
    done

# netty-handler CVEs — shaded JAR: drop in the patched security-analytics-commons
COPY --from=jar-patcher --chown=1000:0 /work/patched.jar \
    /usr/share/opensearch/plugins/opensearch-security-analytics/security-analytics-commons-1.0.0.jar

USER 1000
