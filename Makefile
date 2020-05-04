.PHONY: \
	clean \
	coveralls \
	deploy-ci \
	distclean \
	docs \
	example \
	install \
	lint \
	lint-only \
	list-outdated \
	test \
	test-only

# Project constants
PROJECT = rororo
DOCS_DIR = ./docs

# Project vars
POETRY ?= poetry
PRE_COMMIT ?= pre-commit
PYTHON ?= $(POETRY) run python
TOX ?= tox

# Docs vars
DOCS_HOST ?= localhost
DOCS_PORT ?= 8240

all: install

clean:
	find . \( -name __pycache__ -o -type d -empty \) -exec rm -rf {} + 2> /dev/null

coveralls:
	-$(PYTHON) -m coveralls

deploy-ci:
ifeq ($(TWINE_USERNAME),)
	# TWINE_USERNAME env var should be supplied
	exit 1
endif
ifeq ($(TWINE_PASSWORD),)
	# TWINE_PASSWORD env var should be supplied
	exit 1
endif
ifeq ($(CIRCLECI),)
	$(MAKE) test
endif
	-rm -rf build/ dist/
	$(POETRY) build
	$(POETRY) publish -u $(TWINE_USERNAME) -p $(TWINE_PASSWORD)

distclean: clean
	rm -rf build/ dist/ *.egg*/ .venv/

docs: install
	$(PYTHON) -m pip install -r docs/requirements.txt
	$(POETRY) run sphinx-autobuild -B -H $(DOCS_HOST) -p $(DOCS_PORT) -b html $(DOCS_DIR)/ $(DOCS_DIR)/_build/

example: install
ifeq ($(EXAMPLE),)
	# USAGE: make EXAMPLE=(hobotnica|petstore) example
else
	PYTHONPATH=examples $(PYTHON) -m aiohttp.web $(EXAMPLE).app:create_app
endif

install: .install
.install: pyproject.toml poetry.lock
	$(POETRY) config virtualenvs.in-project true --local
	$(POETRY) install
	touch $@

lint: install lint-only

lint-only:
	SKIP=$(SKIP) $(PRE_COMMIT) run --all $(HOOK)

list-outdated: install
	$(POETRY) show -o

open-docs: docs
	open $(DOCS_DIR)/_build/html/index.html

test: install clean lint validate test-only

test-only:
	TOXENV=$(TOXENV) $(TOX) $(TOX_ARGS) -- $(TEST_ARGS)

validate: install
	$(PYTHON) -m openapi_spec_validator examples/hobotnica/openapi.yaml
	$(PYTHON) -m openapi_spec_validator examples/petstore/petstore-expanded.yaml
	$(PYTHON) -m openapi_spec_validator examples/todobackend/openapi.yaml
	$(PYTHON) -m openapi_spec_validator tests/openapi.json
	$(PYTHON) -m openapi_spec_validator tests/openapi.yaml
