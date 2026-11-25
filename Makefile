.PHONY: test validate evaluate coverage
test:
	python3 -m unittest discover -s tests -v
validate:
	python3 -m sysmonlab validate
evaluate:
	python3 -m sysmonlab evaluate
coverage:
	python3 -m sysmonlab coverage > docs/coverage.md
	python3 -m sysmonlab coverage --layer docs/attack-layer.json
