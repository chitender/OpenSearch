# Stage 1: Patch the official OpenSearch image
# Fixes the following CVEs without a full source build:
#
# OS (libsolv):
#   CVE-2026-48863  stack overflow in EdDSA PGP signature verification
#   CVE-2026-48864  heap overflow via unchecked decompression
#   CVE-2026-9149   heap overflow via negative maxsize in repo_add_solv
#   CVE-2026-9150   stack overflow in Debian metadata SHA384/SHA512 parser
#
# Java (io.netty:netty-handler 4.1.133.Final → 4.2.15.Final in plugins):
#   CVE-2026-44249  IPv6 subnet rule bypass via incorrect masking
#   CVE-2026-45416  DoS via eager buffer allocation in TLS
#   CVE-2026-50010  hostname verification bypass via improper trust manager

FROM opensearchproject/opensearch:3.7.0

USER root

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Fix libsolv OS CVEs (patched in 0.7.22-1.amzn2023.0.4)
RUN dnf -y upgrade libsolv && dnf clean all && rm -rf /var/cache/dnf

# Fix netty-handler CVEs in bundled plugins (e.g. opensearch-security-analytics).
# netty-handler-4.2.15.Final.jar is already present in modules/transport-netty4/,
# so no external download is needed — we copy it over the vulnerable 4.1.x JARs.
# Uses bash globs and parameter expansion only (no findutils required in minimal image).
RUN set -eux; \
    netty_src=''; \
    for f in /usr/share/opensearch/modules/transport-netty4/netty-handler-*.jar; do \
        [ -f "$f" ] && netty_src="$f" && break; \
    done; \
    if [ -n "${netty_src}" ]; then \
        for vuln_jar in /usr/share/opensearch/plugins/*/netty-handler-*.jar; do \
            [ -f "${vuln_jar}" ] || continue; \
            plugin_dir="${vuln_jar%/*}"; \
            jar_name="${netty_src##*/}"; \
            echo "Replacing: ${vuln_jar} -> ${jar_name}"; \
            rm -f "${vuln_jar}"; \
            cp "${netty_src}" "${plugin_dir}/"; \
            chmod 644 "${plugin_dir}/${jar_name}"; \
        done; \
    else \
        echo "WARNING: no netty-handler JAR found in transport-netty4 module"; \
    fi

USER 1000
