FROM registry.access.redhat.com/ubi9-minimal
LABEL maintainer="squad:git-defenders" url="https://github.ibm.com/whitewater/whitewater-detect-secrets"

USER root
# install python 3.11 and corresponding pip ... install git (used in DS scan)
# UBI 8 ships python3.9 at most; UBI 9 ships python3.11 which meets >=3.10 requirement.
RUN microdnf -y install python3.11 python3.11-pip git && \
    microdnf -y update && \
    microdnf clean all
