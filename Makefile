all: install

install:
	python3 -m build
	pip uninstall revizor-fuzzer
	pip install dist/revizor_fuzzer-1.2.3-py3-none-any.whl

uninstall:
	pip uninstall revizor-fuzzer

test:
	./src/tests/runtests.sh

test_pre_release:
	./src/tests/pre-release.sh

site_local:
	mkdocs serve
