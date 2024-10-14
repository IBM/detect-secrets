FROM git-defenders/detect-secrets:redhat-ubi-amd64

COPY scripts/run-in-pipeline.sh /

ENTRYPOINT [ "/run-in-pipeline.sh" ]
CMD [ ]
