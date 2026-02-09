.PHONY: build test vet check rust-crypto dashboard-build pytools-check

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

rust-crypto:
	./scripts/build-rust-crypto.sh

dashboard-build:
	cd dashboard && npm install && npm run build

pytools-check:
	python3 -m py_compile tools/*.py

check: test vet pytools-check
