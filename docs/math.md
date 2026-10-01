# Number theory (`kleptography.math`)

The `math` package holds the pure number theory the schemes rely on. It
imports nothing from the project and works on plain Python integers, so it
can be read and tested on its own.

| Module | Contents | External dependency |
| --- | --- | --- |
| `math.modular` | `mod_pow`, `mod_inverse`, `is_coprime` | none (standard library) |
| `math.primes` | `generate_safe_prime`, `generate_subgroup_generator` | `sympy` |

## Why these functions

Finite-field Diffie-Hellman works in the multiplicative group of integers
modulo a prime `p`. The project uses **safe primes**, `p = 2q + 1` with `q`
also prime, because then the squares modulo `p` form a subgroup of prime
order `q`. Working in a subgroup of prime order has two advantages:

- every element other than 1 generates the whole subgroup, and
- exponents can be reduced modulo `q`, which the Young–Yung SETUP needs
  (see [setup.md](setup.md)).

`mod_pow` and `mod_inverse` are the two operations everything else is built
on: exponentiation for public keys and shared secrets, inversion for the
divisions modulo `p` in the SETUP.

## `math.modular`

### `mod_pow(base, exponent, modulus) -> int`

Returns `base^exponent mod modulus`. It is a thin wrapper around Python's
built-in three-argument `pow`, which already uses fast exponentiation
(square and multiply). Crypto code calls it instead of `pow` so that every
modular exponentiation goes through one place.

- Raises `ValueError` if `modulus <= 0`.

### `mod_inverse(value, modulus) -> int`

Returns the integer `inverse` such that `value * inverse ≡ 1 (mod modulus)`.
An inverse exists if and only if `value` and `modulus` are coprime. Modulo a
prime `p`, every value in `[1, p - 1]` has one, which is what makes
"division modulo `p`" possible: `x / y` means `x * mod_inverse(y, p)`.

- Raises `ValueError` if `modulus <= 1`, or if `value` has no inverse
  modulo `modulus`.

### `is_coprime(a, b) -> bool`

Returns whether `gcd(a, b) == 1`.

### Example

```python
from kleptography.math.modular import is_coprime, mod_inverse, mod_pow

assert mod_pow(2, 6, 23) == 18  # 2^6 = 64 = 2 * 23 + 18
assert mod_inverse(18, 23) == 9  # 18 * 9 = 162 = 7 * 23 + 1
assert (18 * mod_inverse(18, 23)) % 23 == 1
assert is_coprime(6, 11)
assert not is_coprime(6, 9)  # so mod_inverse(6, 9) raises ValueError
```

## `math.primes`

### `generate_safe_prime(bits) -> int`

Returns a random safe prime `p = 2q + 1` of exactly `bits` bits.

1. Sample a random prime `q` of `bits - 1` bits with `sympy.randprime`.
2. Compute `p = 2q + 1` and test it with `sympy.isprime`.
3. Repeat until `p` is prime.

- Raises `ValueError` if `bits < 3`.
- The randomness comes from `sympy`, which is fine for generating
  **insecure toy groups**, the only use of this function. Standardized groups
  are never generated: they are fixed constants (see
  [dh.md](dh.md#standardized-groups-rfc-7919)).

### `generate_subgroup_generator(prime) -> int`

Returns a generator of the subgroup of order `q = (p - 1) / 2` modulo a safe
prime `p`.

It takes the smallest primitive root `r` modulo `p` (an element of order
`p - 1`, found by `sympy.primitive_root`) and returns `r^2 mod p`. Squaring
halves the order, so the result has order exactly `q`. The result is
deterministic: the same `p` always gives the same generator.

- Raises `ValueError` if `prime` is not prime or not a safe prime.
- Raises `RuntimeError` if `sympy` finds no primitive root (which cannot
  happen for a prime).

### Example

```python
from kleptography.math.modular import mod_pow
from kleptography.math.primes import (
    generate_safe_prime,
    generate_subgroup_generator,
)

assert generate_subgroup_generator(23) == 2  # 5 is a primitive root; 5^2 = 25 ≡ 2

p = generate_safe_prime(16)  # random, e.g. 57803
q = (p - 1) // 2
g = generate_subgroup_generator(p)
assert p.bit_length() == 16
assert mod_pow(g, q, p) == 1  # g lies in the subgroup of order q
```

## Where these functions are used

| Function | Used by |
| --- | --- |
| `mod_pow` | DH validation, public keys and shared secrets ([dh.md](dh.md)); SETUP derivation and recovery ([setup.md](setup.md)) |
| `mod_inverse` | SETUP divisions modulo `p`: `z1 = m1 / r^X`, `z2 = z1 / g^W` ([setup.md](setup.md)) |
| `generate_safe_prime`, `generate_subgroup_generator` | `DiffieHellmanParameters.generate_toy` ([dh.md](dh.md)) |

## Limitations

- Python integers have no constant-time arithmetic: execution time can
  depend on secret values. This is acceptable for an educational project
  and is one of the production protections it deliberately omits.
- Primality is checked with `sympy.isprime`, which is a strong probable-prime
  test. It is reliable for the sizes used here.
