FROM splunk/splunk:10.4.1@sha256:af4f671c9c931bfd80954e7f1baaff8540d1378ae26b098666cf05256bb24311

LABEL org.opencontainers.image.title="Tracecat Lab 001 Splunk target" \
      org.opencontainers.image.source="https://github.com/TracecatHQ/labs" \
      org.opencontainers.image.licenses="LicenseRef-Splunk-Enterprise AND CC-BY-NC-SA-4.0" \
      org.tracecat.lab.id="001"

USER root

COPY --chown=splunk:splunk assets/dataset/conf/ /lab/conf/
COPY --chown=splunk:splunk assets/dataset/logs/ /lab/logs/
COPY --chown=splunk:splunk target/splunk/conf/ /lab/conf/
COPY assets/splunk-mcp-server_200.tgz /tmp/splunk-mcp-server.tgz
RUN mkdir /tmp/splunk-mcp-server /lab/assets \
    && tar -xzf /tmp/splunk-mcp-server.tgz -C /tmp/splunk-mcp-server \
    && sed -i '/"pattern": ".*(?/d' /tmp/splunk-mcp-server/Splunk_MCP_Server/default/builtin_tools.json \
    && tar -czf /lab/assets/splunk-mcp-server_200.tgz -C /tmp/splunk-mcp-server Splunk_MCP_Server \
    && chown -R splunk:splunk /lab/assets
COPY --chown=splunk:splunk assets/dataset/README.md assets/dataset/LICENSE assets/dataset/LICENSE-DATA /usr/share/doc/lab-001/
COPY --chmod=0755 target/splunk/entrypoint.sh /sbin/lab-001-entrypoint.sh
COPY --chmod=0755 target/splunk/healthcheck.sh /opt/lab/healthcheck.sh

ENV LAB_NAME="lab-001"

USER ansible
ENTRYPOINT ["/sbin/lab-001-entrypoint.sh"]
CMD ["start-service"]
