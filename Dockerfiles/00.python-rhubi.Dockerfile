FROM registry.access.redhat.com/ubi8/python-39
LABEL maintainer="squad:git-defenders" url="https://github.ibm.com/whitewater/whitewater-detect-secrets"

# Note: upgrading pip in the RedHat UBI image at this point, othersise it will fail the pip image later
#  - instead of using the a wheel - it will fallback on the Legancy setuptools and fail on install of detect-secrets
# RUN pip install --upgrade pip
