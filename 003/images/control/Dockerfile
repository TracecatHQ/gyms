ARG NUCLEI_IMAGE=projectdiscovery/nuclei:v3.4.10@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97
ARG TRACECAT_IMAGE=ghcr.io/tracecathq/tracecat:1.0.0-beta.52-rc.22@sha256:a1efce2a90593a269bc23a0ff555df53990f786c9e5dca30ea6249b3c76f1ea2
FROM ${NUCLEI_IMAGE} AS nuclei

FROM ${TRACECAT_IMAGE}

ARG GYM_INPUT_SHA
ARG GYM_REVISION
ARG TRACECAT_VERSION
ARG GYM_COMPONENT_VERSION

LABEL org.opencontainers.image.title="Tracecat Gym 003 control plane" \
      org.opencontainers.image.description="Fixed-target scanner, WAF policy controller, and evidence collector" \
      org.opencontainers.image.source="https://github.com/TracecatHQ/gyms" \
      org.opencontainers.image.revision="${GYM_REVISION}" \
      org.opencontainers.image.version="${GYM_COMPONENT_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.tracecat.gym.id="003" \
      org.tracecat.gym.input-sha="${GYM_INPUT_SHA}" \
      org.tracecat.gym.upstream-version="${TRACECAT_VERSION}" \
      org.tracecat.gym.nuclei.version="3.4.10"

USER root
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=gymctl --chown=apiuser:apiuser *.py /opt/gym/src/gymctl/
COPY --chown=apiuser:apiuser src/gym_plugin/*.py /opt/gym/src/gym_plugin/
COPY --chown=apiuser:apiuser benchmark/ /opt/gym/benchmark/
COPY --chown=apiuser:apiuser assets/ /opt/gym/assets/
COPY --chown=apiuser:apiuser gym.lock.json PROVENANCE.md /opt/gym/
COPY --chmod=0755 images/control/receipt_service.py /opt/gym/bin/
USER apiuser

ENV GYM_ROOT="/opt/gym" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONPATH="/opt/gym/src:/app/packages/tracecat-admin:/app"
ENTRYPOINT ["/app/.venv/bin/python", "-m", "gymctl"]
