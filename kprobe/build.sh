apt install llvm clang

export BPF_CLANG=clang

go generate

go build .