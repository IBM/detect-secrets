FROM git-defenders/cli-rhubi

# Ensure no trivy violation for PIP
RUN pip install --upgrade pip

ENTRYPOINT [ "/run-in-pipeline.sh" ]
CMD [ ]
