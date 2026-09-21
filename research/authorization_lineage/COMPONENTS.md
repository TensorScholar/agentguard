# Component separation

The DEV implementation is intentionally separated into components that will be frozen independently before confirmatory execution:

1. A1 authorization-instance extension (`ledger.py` + A1 wrapper in `arms.py`).
2. B4 strong conventional ledger (`ledger.py` + B4 wrapper in `arms.py` + `fence.py`).
3. Provider/oracle (`provider.py`).
4. Harness (`harness.py`).
5. Analysis/manifest (`analysis.py`).

A0 remains pinned to commit `7e5659a26ee232e2a7352a20b2b3bd87a1b4e0cf` and is not redefined by this branch.
