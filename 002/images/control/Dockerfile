ARG TRACECAT_IMAGE
FROM ${TRACECAT_IMAGE}

ARG GYM_INPUT_SHA
ARG GYM_REVISION
ARG TRACECAT_VERSION
ARG GYM_COMPONENT_VERSION

LABEL org.opencontainers.image.title="Tracecat Gym 002 control plane" \
      org.opencontainers.image.description="Bootstrap and reconciliation for the BOTSv3 gym" \
      org.opencontainers.image.source="https://github.com/TracecatHQ/gyms" \
      org.opencontainers.image.revision="${GYM_REVISION}" \
      org.opencontainers.image.version="${GYM_COMPONENT_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.tracecat.gym.id="002" \
      org.tracecat.gym.input-sha="${GYM_INPUT_SHA}" \
      org.tracecat.gym.upstream-version="${TRACECAT_VERSION}"

USER root
COPY --chown=apiuser:apiuser src/ /opt/gym/src/
COPY --chown=apiuser:apiuser data/ /opt/gym/data/
COPY --chown=apiuser:apiuser ANALYST_INSTRUCTIONS.md agent-preset.json gym.lock.json /opt/gym/
USER apiuser

ENV PYTHONPATH="/opt/gym/src:/app/packages/tracecat-admin:/app"
ENTRYPOINT ["/app/.venv/bin/python", "-m", "gymctl"]
