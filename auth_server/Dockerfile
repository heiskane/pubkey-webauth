FROM python:3.10-bookworm as build

RUN pip install poetry

COPY pyproject.toml poetry.lock ./

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

RUN poetry install --no-root && rm -rf $POETRY_CACHE_DIR

FROM python:3.10-bookworm as work

ENV VIRTUAL_ENV=/.venv \
    PATH="/.venv/bin:$PATH"

COPY --from=build ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY ./ /auth_server

WORKDIR /auth_server

CMD [ "python3", "-m", "auth_server" ]
