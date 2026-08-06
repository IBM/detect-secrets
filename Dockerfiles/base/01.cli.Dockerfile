FROM git-defenders/python

RUN \
  # Auto adjust line ending. Support running scan on Windows platform
  git config --system core.autocrlf true && \
  # Improve performance when creating index across Windows and Linux platform
  git config --system core.checkStat minimal

COPY setup.py setup.cfg /code/
COPY detect_secrets /code/detect_secrets

# Install the package — deps are pinned in setup.py install_requires.
# pyahocorasick is declared under extras_require['word_list'] so install explicitly.
RUN pip install /code && \
    pip install 'pyahocorasick==2.3.1'

# Generate pipenv lock file under /, it will be picked up by trivy
COPY scripts/gen-pipfile.sh /
RUN /gen-pipfile.sh > /Pipfile && pip install pipenv && pipenv --python `which python3` && pipenv lock

WORKDIR /code
