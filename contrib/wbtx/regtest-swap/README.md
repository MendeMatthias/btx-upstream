# BTX↔EVM swap tooling on regtest

`swap_tests.py` drives `contrib/wbtx/btx_wbtx.py` against throwaway regtest
nodes (stdlib Python, no test framework): a swap across two separate chains,
the refund and claim guards, fees and replacement, already-refundable
locks, the SDK's live timeout check, and (with `--peer-bindir`) two versions
on one chain. Regtest coins only; the nodes live in a temp folder on
127.0.0.1 and are stopped and deleted at the end.

```bash
python3 -I contrib/wbtx/regtest-swap/swap_tests.py <bin dir with btxd> contrib/wbtx/btx_wbtx.py [--peer-bindir <another version's bin dir>]
```

Each scenario prints PASS, FINDING or FAIL with its evidence.
