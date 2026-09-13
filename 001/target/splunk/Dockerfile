FROM splunk/splunk:10.4.1@sha256:af4f671c9c931bfd80954e7f1baaff8540d1378ae26b098666cf05256bb24311

LABEL org.opencontainers.image.title="Tracecat Gym 001 Splunk target" \
      org.opencontainers.image.source="https://github.com/TracecatHQ/gyms" \
      org.opencontainers.image.licenses="LicenseRef-Splunk-Enterprise AND CC-BY-NC-SA-4.0" \
      org.tracecat.gym.id="001"

USER root

COPY --chown=splunk:splunk assets/dataset/conf/ /lab/conf/
COPY --chown=splunk:splunk assets/dataset/logs/ /lab/logs/
COPY --chown=splunk:splunk target/splunk/conf/ /lab/conf/
COPY --chown=splunk:splunk assets/splunk-mcp-server_200.tgz /lab/assets/splunk-mcp-server_200.tgz
COPY --chown=splunk:splunk assets/dataset/README.md assets/dataset/LICENSE assets/dataset/LICENSE-DATA /usr/share/doc/gym-001/
COPY --chmod=0755 target/splunk/entrypoint.sh /sbin/gym-001-entrypoint.sh
COPY --chmod=0755 target/splunk/healthcheck.sh /opt/gym/healthcheck.sh

ENV LAB_NAME="gym-001"

USER ansible
ENTRYPOINT ["/sbin/gym-001-entrypoint.sh"]
CMD ["start-service"]
