"""Opt-in signer backends.

The stdlib HMAC default lives in :mod:`mig.evidence.signing`. These backends are
imported lazily by ``make_signer``/``make_verifier`` so the core import graph
stays stdlib-only (I10): ``ed25519`` needs the ``cryptography`` extra
(``mig[signing]``); ``cosign`` drives the host ``cosign`` binary and needs no
Python dependency.
"""
