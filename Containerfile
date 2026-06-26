# OCI container image that installs DAVIX from CERN
# Build with: podman build -t davix .
# Reference: https://dmc.web.cern.ch/projects/davix/home

FROM almalinux:9

LABEL org.opencontainers.image.title="davix" \
      org.opencontainers.image.description="DAVIX - file management and transfer tools from CERN" \
      org.opencontainers.image.source="https://github.com/ericvaandering/davix-explore" \
      org.opencontainers.image.url="https://dmc.web.cern.ch/projects/davix/home"

# Install EPEL (Extra Packages for Enterprise Linux) and then davix
RUN dnf install -y epel-release && \
    dnf install -y davix voms-clients-cpp && \
    dnf clean all && \
    rm -rf /var/cache/dnf

# Keep the container running indefinitely so it can be exec'd into, e.g.:
#   podman exec -it <container> bash
CMD ["sleep", "infinity"]
