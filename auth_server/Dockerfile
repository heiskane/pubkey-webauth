FROM python:3.10-bookworm

COPY auth_server/ ./auth_server

WORKDIR /auth_server

# TODO: multistage build
COPY pyproject.toml poetry.lock ./
RUN pip install poetry 
RUN poetry config virtualenvs.create false
RUN poetry install --only main

CMD [ "python3", "auth_server/main.py" ]
# CMD [ "ls", "-la", "auth_server" ]
