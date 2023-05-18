.PHONY: update master release setup update_master update_release build clean

setup:
	git config --global --add url."git@gitlab.com:".insteadOf "https://gitlab.com/"

clean:
	rm -rf vendor/
	go mod vendor

update:
	-GOFLAGS="" go get -u all

build:
	go build ./...
	go mod tidy

update_release:
	GOFLAGS="" go get gitlab.com/elixxir/wasm-utils@release
	GOFLAGS="" go get gitlab.com/xx_network/primitives@release
	GOFLAGS="" go get gitlab.com/elixxir/primitives@release
	GOFLAGS="" go get gitlab.com/xx_network/crypto@release

update_master:
	GOFLAGS="" go get gitlab.com/elixxir/wasm-utils@master
	GOFLAGS="" go get gitlab.com/xx_network/primitives@master
	GOFLAGS="" go get gitlab.com/elixxir/primitives@master
	GOFLAGS="" go get gitlab.com/xx_network/crypto@master

master: update_master clean build

release: update_release clean build

wasmException = "vendor/gitlab.com/elixxir/wasm-utils/exception"

wasm_tests:
	echo $(wasmException)
	cp $(wasmException)/throw_js.s $(wasmException)/throw_js.s.bak
	cp $(wasmException)/throws.go $(wasmException)/throws.go.bak
	> $(wasmException)/throw_js.s
	cp $(wasmException)/throws.dev $(wasmException)/throws.go
	-GOOS=js GOARCH=wasm go test -v ./rsa/...
	mv $(wasmException)/throw_js.s.bak $(wasmException)/throw_js.s
	mv $(wasmException)/throws.go.bak $(wasmException)/throws.go
