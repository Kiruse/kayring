# Kayring - Kiru's Keyring
*Kayring* is a simple encrypted keyring designed for cryptocurrency private key management in deployment and automated pipelines.

# Usage
Kayring provides a couple of commands:

- `set <name> [--value]` - Set the private key with the given name. If the private key already exists, it will not be added unless `--force` is specified. If `value` is not given, the program will prompt you unless `--silent`. If silent, a missing `value` will cause an error instead, and a `--password` must be specified as well, otherwise it will be assumed to be empty.
- `get <name>` - Get the private key by the given name. If `--silent`, a `--password` must be specified as well, otherwise it will be assumed to be empty.
- `list` - List all keystores.

Certain arguments such as `value`, `password`, `dir` and `derivation_rounds` can be passed in through SHOUTY_SNAKE_CASED environment variables prefixed with `KAYRING_`. This is helpful to configure environments or for automated processes and work well with the `--silent` option.
