FROM bcgovimages/von-image:py36-1.16-0

RUN pip3 install --no-cache-dir poetry

RUN mkdir acapy_plugin_toolbox; touch acapy_plugin_toolbox/__init__.py
COPY README.md .
COPY docker/default.yml .
COPY pyproject.toml poetry.lock .
USER root
RUN chown -R indy:indy .
USER $user

RUN poetry install --no-dev

# Make site packages location more accessible (for use with volumes)
RUN ln -s $(poetry env info -p)/lib/python3.6/site-packages site-packages

COPY default.mrgf.json .
COPY acapy_plugin_toolbox acapy_plugin_toolbox

ENTRYPOINT ["/bin/bash", "-c", "poetry run aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
