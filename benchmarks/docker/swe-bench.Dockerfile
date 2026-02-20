ARG PYTHON_VERSION=3.9
FROM python:${PYTHON_VERSION}-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential gcc g++ gfortran pkg-config \
    libffi-dev libxml2-dev libxslt1-dev libyaml-dev \
    liblapack-dev libblas-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /repo
COPY . /repo

RUN git config --global user.email "bench@ironclaw" \
    && git config --global user.name "Bench"

# Try multiple install strategies: bare, [dev], [test].
# Some repos only define extras, so we try each in order.
RUN pip install --upgrade pip setuptools wheel \
    && pip install -e . 2>/dev/null \
    || pip install -e ".[dev]" 2>/dev/null \
    || pip install -e ".[test]" 2>/dev/null \
    || echo "WARN: pip install -e . failed, tests may lack dependencies"

# Ensure pytest is available even if the repo doesn't declare it.
RUN pip install pytest 2>/dev/null || true
