FROM registry.access.redhat.com/ubi8-minimal as base
LABEL maintainer="squad:git-defenders" url="https://github.ibm.com/whitewater/whitewater-detect-secrets"

User root
# install python 3.8 and corresponding pip ... install git (used in DS scan)
RUN microdnf -y install python38 python38-pip python38-devel git cargo openssl-devel
RUN microdnf -y update

RUN pip3 install --upgrade pip setuptools wheel


FROM base

COPY README.md /code/
COPY setup.py /code/
COPY setup.cfg /code/
COPY detect_secrets /code/detect_secrets

RUN pip3 install /code

WORKDIR /code

ENTRYPOINT [ "detect-secrets" ]
CMD [ "scan", "/code" ]
