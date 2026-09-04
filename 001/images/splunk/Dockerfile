ARG SPLUNK_IMAGE
FROM ${SPLUNK_IMAGE}

ARG GYM_INPUT_SHA
ARG GYM_REVISION
ARG DATASET_COMMIT
ARG SPLUNK_VERSION
ARG MCP_VERSION
ARG GYM_COMPONENT_VERSION

LABEL org.opencontainers.image.title="Tracecat Gym 001 Splunk appliance" \
      org.opencontainers.image.description="Splunk, MCP Server, and the pinned Gym 001 telemetry" \
      org.opencontainers.image.source="https://github.com/TracecatHQ/gyms" \
      org.opencontainers.image.revision="${GYM_REVISION}" \
      org.opencontainers.image.version="${GYM_COMPONENT_VERSION}" \
      org.opencontainers.image.licenses="LicenseRef-Splunk-Enterprise AND CC-BY-NC-SA-4.0" \
      org.tracecat.gym.id="001" \
      org.tracecat.gym.input-sha="${GYM_INPUT_SHA}" \
      org.tracecat.gym.upstream-version="${SPLUNK_VERSION}" \
      org.tracecat.gym.dataset.commit="${DATASET_COMMIT}" \
      org.tracecat.gym.splunk.version="${SPLUNK_VERSION}" \
      org.tracecat.gym.mcp.version="${MCP_VERSION}"

USER root

COPY --chown=splunk:splunk upstream/dataset/conf/ /lab/conf/
COPY --chown=splunk:splunk upstream/dataset/logs/ /lab/logs/
COPY --chown=splunk:splunk images/splunk/conf/ /lab/conf/
COPY --chown=splunk:splunk assets/splunk-mcp-server_200.tgz /lab/assets/splunk-mcp-server_200.tgz
COPY --chown=splunk:splunk gym.lock.json /opt/gym/gym.lock.json
COPY --chown=splunk:splunk upstream/dataset/README.md upstream/dataset/LICENSE upstream/dataset/LICENSE-DATA /usr/share/doc/gym-001/
COPY --chmod=0755 images/splunk/entrypoint.sh /sbin/gym-001-entrypoint.sh
COPY --chmod=0755 images/splunk/healthcheck.sh /opt/gym/healthcheck.sh

ENV LAB_NAME="gym-001"

USER ansible
ENTRYPOINT ["/sbin/gym-001-entrypoint.sh"]
CMD ["start-service"]
