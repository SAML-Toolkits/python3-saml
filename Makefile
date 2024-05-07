PIP=pip
BLACK=black
FLAKE8=flake8
PYTEST=pytest
COVERAGE=coverage
COVERAGE_CONFIG=tests/coverage.rc
MAIN_SOURCE=src/onelogin/saml2
DEMOS=demo-django demo-flask demo-tornado demo_pyramid
TESTS=tests/src/OneLogin/saml2_tests
SOURCES=$(MAIN_SOURCE) $(DEMOS) $(TESTS)

install-req:
	$(PIP) install .

install-test:
	$(PIP) install -e ".[test]"

pytest:
	$(COVERAGE) run --source $(MAIN_SOURCE) --rcfile=$(COVERAGE_CONFIG) -m pytest
	$(COVERAGE) report -m --rcfile=$(COVERAGE_CONFIG)

black:
	$(BLACK) $(SOURCES)

flake8:
	$(FLAKE8) $(SOURCES)

clean:
	rm -rf .pytest_cache/
	rm -rf .eggs/
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type d -name "*.egg-info" -exec rm -r {} +
	rm .coverage
