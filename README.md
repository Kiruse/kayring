# Kayring - Kiru's Keyring
*Kayring* is a simple encrypted keyring designed for cryptocurrency private key management in deployment and automated pipelines.

# Usage
Kayring provides a couple of commands:

- `set <name> [--value]` - Set the private key with the given name. If the private key already exists, it will not be added unless `--force` is specified. If `value` is not given, the program will prompt you unless `--silent`. If silent, a missing `value` will cause an error instead, and a `--password` must be specified as well, otherwise it will be assumed to be empty.
- `get <name>` - Get the private key by the given name. If `--silent`, a `--password` must be specified as well, otherwise it will be assumed to be empty.
- `list` - List all keystores.
- `clone <from> <to>` - Clone the given keystore. The cloned keystore will have the exact same key, password, and settings. Useful for reusing the same key whilst retaining some flexibility in the associative name.

Certain arguments such as `value`, `password`, `dir` and `derivation_rounds` can be passed in through SHOUTY_SNAKE_CASED environment variables prefixed with `KAYRING_`. This is helpful to configure environments or for automated processes and work well with the `--silent` option.

# Caveat
I am not a professional cryptographer. I am merely a hobbyist. I cannot guarantee that this utility tool adheres to industry standards & best practices. Use this tool at your own risk.

# License
The MIT License (MIT)
Copyright © 2024 Kiruse

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
