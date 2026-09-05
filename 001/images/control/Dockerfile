ARG TRACECAT_IMAGE
FROM ${TRACECAT_IMAGE}

ARG GYM_INPUT_SHA
ARG GYM_REVISION
ARG TRACECAT_VERSION
ARG GYM_COMPONENT_VERSION

LABEL org.opencontainers.image.title="Tracecat Gym 001 control plane" \
      org.opencontainers.image.description="Bootstrap, reconciliation, MCP compatibility, and evaluation for Gym 001" \
      org.opencontainers.image.source="https://github.com/TracecatHQ/gyms" \
      org.opencontainers.image.revision="${GYM_REVISION}" \
      org.opencontainers.image.version="${GYM_COMPONENT_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.tracecat.gym.id="001" \
      org.tracecat.gym.input-sha="${GYM_INPUT_SHA}" \
      org.tracecat.gym.upstream-version="${TRACECAT_VERSION}" \
      org.tracecat.gym.tracecat.version="${TRACECAT_VERSION}"

USER root
COPY --from=gymctl --chown=apiuser:apiuser *.py /opt/gym/src/gymctl/
COPY --chown=apiuser:apiuser src/gym_plugin/*.py /opt/gym/src/gym_plugin/
COPY --chown=apiuser:apiuser benchmark/ /opt/gym/benchmark/
COPY --chown=apiuser:apiuser gym.lock.json /opt/gym/gym.lock.json
USER apiuser

ENV GYM_ROOT="/opt/gym" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONPATH="/opt/gym/src:/app/packages/tracecat-admin:/app"
ENTRYPOINT ["/app/.venv/bin/python", "-m", "gymctl"]
