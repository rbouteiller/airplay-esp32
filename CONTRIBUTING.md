# Contributing

## Formatting

This project uses `clang-format` 22.1.4 for C and header files. Use the pinned
development dependency so local formatting matches CI:

```sh
python3 -m pip install --user -r requirements-dev.txt
scripts/format.sh
```

To check formatting without changing files:

```sh
scripts/format.sh --check
```
