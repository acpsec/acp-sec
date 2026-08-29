# SCRATCH — intentionally-failing Dockerfile to prove branch protection blocks a
# red docker-build check. This PR must NOT be merged. Delete branch after.
FROM alpine:latest
RUN exit 1
