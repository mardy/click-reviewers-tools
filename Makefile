all:
	# Use setup.py to install
	exit 1

install: all

test:
	./run-tests

syntax-check: clean
	./run-pep8

check: test syntax-check

clean:
	rm -rf ./clickreviews/__pycache__ ./clickreviews/tests/__pycache__
