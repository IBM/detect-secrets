FROM git-defenders/cli-ubi

# Ensure no trivy violation for pip
RUN pip install --upgrade pip

ENTRYPOINT [ "/run-in-pipeline.sh" ]
CMD [ ]
