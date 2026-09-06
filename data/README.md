# data/

## loldrivers_reference.csv

This file ships with **5 sample rows only**, so the pipeline is runnable
out of the box without any network access. The hashes are illustrative
placeholders — they are NOT real vulnerable driver hashes, and matching
against them will never produce a false real-world positive.

Before running the project for real, replace this file with the actual
LOLDrivers dataset:

```bash
# Full JSON dataset (recommended — richest fields)
curl -L -o loldrivers_full.json \
  https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/yml/loldrivers.json

# Or the CSV export
curl -L -o loldrivers_full.csv \
  https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/loldrivers.csv
```

Then run:

```bash
python scripts/build_loldrivers_reference.py loldrivers_full.json data/loldrivers_reference.csv
```

to normalize it to the schema the detector expects:
`driver_name, sha256, category, verified_vulnerable`.

## raw/ and processed/

Created automatically by `scripts/evtx_to_csv.py` and
`detection/simulate_harness.py`. Both are gitignored except for small
sample files — real exported EVTX/CSV logs should never be committed,
since they can contain host-identifying information.
