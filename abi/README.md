# The C ABI macula-py binds

`macula.h` is a verbatim copy of `cabi/macula.h` from macula-go at the ref in
`MACULA_GO_REF` (a macula-go release tag and the commit it must name; both
scripts refuse a tag that has moved). `tests/test_abi_declarations.py` fails when the ctypes
declarations in `src/macula_py/_abi.py` and this header disagree, and CI fails
when this copy differs from the header at that ref. To move to a new macula-go
release: put its tag and commit in `MACULA_GO_REF`, copy its header here, and fix what the tests
name.
