FROM python:3.10-bookworm as build

RUN pip install poetry

COPY pyproject.toml poetry.lock ./

RUN poetry install --no-root
RUN poetry export -f requirements.txt --output requirements.txt

FROM python:3.10-bookworm as work

COPY --from=build requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY ./ /auth_server

CMD [ "python3", "-m", "auth_server" ]
