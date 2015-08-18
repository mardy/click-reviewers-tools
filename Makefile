all:
	# Use setup.py to install
	exit 1

install: all

test:
	./run-tests

syntax-check: clean
	./run-pyflakes
	./run-pep8

check: test syntax-check

clean:
	rm -rf ./clickreviews/__pycache__ ./clickreviews/tests/__pycache__

check-names:
	@./collect-check-names 2>&1 | grep 'CHECK_NAME|' \
		| cut -d '|' -f 2 \
		| awk -F ':' '{printf("%s:%s\n", $$1, $$2)}' \
		| sort -u | grep -v skeleton | grep -v some-check
