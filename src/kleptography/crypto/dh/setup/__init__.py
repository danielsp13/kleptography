"""
Young-Yung SETUP attack on finite-field Diffie-Hellman (kleptographic DH).

KLEPTOGRAPHIC CODE. This package is intentionally separate from the honest
Diffie-Hellman implementation in ``kleptography.crypto.dh``. It depends on
the honest modules, and they never depend on it.

Reference:
    A. L. Young and M. Yung, "Kleptography: Using Cryptography Against
    Cryptography", EUROCRYPT '97, LNCS 1233, pp. 62-74, Springer, 1997.

Summary (to be checked against the paper in the research issue):

- Targeted cryptosystem: Diffie-Hellman key exchange run by a black-box
  device (the compromised participant).
- Adversarial objective: recover the device's private exponent, and so the
  shared secret, of the second key exchange.
- Attacker knowledge: the attacker's private key ``X`` and the public
  values ``m1 = g^c1`` and ``m2 = g^c2`` observed on the channel.
- SETUP mechanism: the attacker embeds its public key ``Y = g^X`` and the
  constants ``a``, ``b`` and ``W`` (``W`` odd) in the device. The device
  uses a random ``c1`` in the first exchange and stores it. In the second
  exchange it samples ``t`` in ``{0, 1}`` and computes::

      z  = g^(c1 - W*t) * Y^(-a*c1 - b)  mod p
      c2 = H(z)

- Recovery: the attacker computes ``r = m1^a * g^b``, ``z1 = m1 / r^X`` and
  ``z2 = z1 / g^W``. If ``g^H(z1) == m2`` then ``c2 = H(z1)``, otherwise
  ``c2 = H(z2)``.
- Educational point: ``m2`` is a valid DH public value that looks as random
  as an honest one, yet only the holder of ``X`` can recover ``c2``.

Educational simplification: the paper works in Z_p^* with a generator of
order p - 1; this package reuses the project's prime-order subgroup
(``p = 2q + 1``, exponents modulo q). The consequences of that adaptation
are an open question of the research issue.

This code is for education only and is not secure.
"""
