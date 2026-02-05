PIP=pip
BLACK=black
FLAKE8=flake8
PYTEST=pytest
COVERAGE=coverage
COVERAGE_CONFIG=tests/coverage.rc
COVERALLS=coveralls
MAIN_SOURCE=src/python3_saml/saml2
DEMOS=demo-django demo-flask demo-tornado demo_pyramid
TESTS=tests/src/Python3_Saml/saml2_tests
SOURCES=$(MAIN_SOURCE) $(DEMOS) $(TESTS)

install-req:
	$(PIP) install .

install-test:
	$(PIP) install -e ".[test]"

install-lint:
	$(PIP) install -e ".[lint]"

pytest:
	$(PYTEST)

coverage:
	$(COVERAGE) run -m $(PYTEST)
	$(COVERAGE) report -m

coveralls:
	$(COVERALLS)

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
