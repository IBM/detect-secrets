FROM git-defenders/cli-rhubi

# Ensure no trivy violation for pip
RUN pip install --upgrade pip

ENTRYPOINT [ "/run-in-pipeline.sh" ]
CMD [ ]
