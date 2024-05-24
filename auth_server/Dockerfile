FROM python:3.10-bookworm

COPY ./ /auth_server

WORKDIR /auth_server

# TODO: multistage build
COPY pyproject.toml poetry.lock ./
RUN pip install poetry 
RUN poetry config virtualenvs.create false
RUN poetry install

CMD [ "python3", "auth_server/main.py" ]
