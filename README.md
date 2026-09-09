# Kleptography

**Author:** Daniel Pérez Ruiz

> An open-source educational project for studying and demonstrating kleptographic techniques, with a focus on understanding how cryptographic constructions can be modified to leak information while retaining normal-looking behavior.

![Kleptography](docs/images/kleptofox.png)

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![uv](https://img.shields.io/badge/uv-managed-purple)
![Cryptography](https://img.shields.io/badge/Topic-Cryptography-green)
![Kleptography](https://img.shields.io/badge/Topic-Kleptography-red)
![SETUP](https://img.shields.io/badge/Topic-SETUP-yellow)
![Education](https://img.shields.io/badge/Purpose-Education-orange)

## About

Kleptography is an open-source educational software project for studying and demonstrating kleptographic techniques.

The project is primarily inspired by the work of:

> Young and Yung, Kleptography: Using Cryptography Against Cryptography.

The initial cryptographic target is *Diffie-Hellman (DH)*, with potential future work covering other cryptographic mechanisms.

The main goal is education and analysis, rather than the development of deployable malicious cryptographic implementations.

The project explores the distinction between:

* a legitimate cryptographic scheme and its security properties;
* a corresponding kleptographic construction;
* the information intentionally leaked by that construction;
* the assumptions that make the leakage possible; and
* why such behavior can remain difficult to detect.

Every kleptographic demonstration is intended to make these concepts explicit rather than hiding adversarial behavior inside a generic cryptographic API.

## Requirements

- Python 3.12+
- uv

Development dependencies are managed through the project configuration and include:

- `pytest` — testing
- `ruff` — formatting and linting
- `ty` — static type checking

## Usage

### Development

Clone the repository and enter the project directory:

```bash
git clone https://github.com/danielsp13/kleptography.git
cd kleptography
```

Create the project environment and install the development dependencies with `uv`:

```bash
uv sync
```

Run the test suite:

```bash
uv run pytest
```

Run Ruff checks:

```bash
uv run ruff check .
```

Format the project with Ruff:

```bash
uv run ruff format .
```

Run the type checker:

```bash
uv run ty check
```

The `uv.lock` file should be kept under version control so that development environments remain reproducible.

## License

See [LICENSE](LICENSE).