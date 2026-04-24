# Phishmate

This repository contains a Python script that aggregates, normalises and classifies
phishing domain feeds with a focus on Australian entities.  The script uses
`australian_indicators_merged.json` to load brand and keyword indicators.
It can be run on a schedule (e.g. via cron or GitHub Actions) and outputs three
files:

* **banking.txt** – domains that target Australian banking
* **government.txt** – domains that target Australian government
* **utilities.txt** – domains that target Australian utilities or
  telecom services

The classification logic is intentionally conservative: a domain is only
classified if it contains a recognised Australian brand or a strong contextual
signal.

## Features

* **Parallel feed fetching** – downloads all configured feeds concurrently
* **TLD caching** – uses `tldextract` with a local cache to speed up domain
  parsing
* **Whitelist support** – `australian_whitelist.json` contains domains that
  should never be flagged
* **Checkpointing** – progress is saved to disk so a long‑running run can be
  resumed after an interruption
* **Extensible configuration** – all paths, feed URLs and worker counts are
  defined in `config.yaml`

## How it Works

1. **Load configuration** – The script reads `config.yaml` for feed URLs, file
   paths and runtime options.
2. **Download feeds** – Each feed URL is fetched in parallel using a
   `ThreadPoolExecutor`.  The script supports CSV, plain‑text and JSON feeds.
3. **Normalise domains** – URLs are parsed, the host part is extracted and
   normalised (lower‑case, stripped of `www.` and ports).
4. **Classify** – The `classify_host` function applies a large set of
   heuristics to determine whether a domain is banking, government, utilities
   or should be rejected.  The heuristics are based on:
   * Known Australian brand lists (banks, telecoms, utilities)
   * State and city tokens
   * Contextual keywords (e.g. `login`, `secure`, `gov`)
   * Exclusion lists for non‑Australian entities and noise hosts
5. **Output** – Classified domains are written to the three output files in the
   `output` directory.  Rejected domains are logged to `rejection_log` if
   debugging is enabled.

The script is written in Python 3.7+ and has no external dependencies beyond
`requests`, `tldextract`, `pandas` and `pyyaml`.

## Installation

```bash
# Clone the repository
git clone https://github.com/RigaOnTheRocks/Phishmate
cd Phishmate

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

The `requirements.txt` file contains:

```
requests
tldextract
pandas
pyyaml
```

## Usage

Run the script directly:

```bash
python3 australian_phish_feed.py
```

### Command‑line Options

The script accepts a small set of flags that control its behaviour.  The
following table lists each option, its short form, and a brief description.

| Flag | Short form | Description |
|------|------------|-------------|
| `--start` | `-s` | Generate Australian phishing feeds.  This is the default action when no other flags are supplied.
| `--reclassify-feeds` | `-r` | Re‑classify existing feed files without fetching remote sources.  Useful when the classification logic has changed.
| `--compare-feeds` | `-c` | Compare feeds between two dates (YYYY‑MM‑DD) or the latest and previous.  Usage: `--compare-feeds [DATE1] [DATE2]`.

You can also use the standard `-h` or `--help` flag to display this help text.

The script will create the `output` directory if it does not exist and will
populate `banking.txt`, `government.txt` and `utilities.txt`.



## Configuration

All configuration is stored in `config.yaml`.  

⚠️ "feeds" inside the yaml file are the data sources we're pulling from, not the location of our generated feeds.

Key sections include:
```yaml
feeds:
  - https://example.com/phishing.txt

output:
  output_dir: ./output
  archive_dir: ./archive
  rejection_log: ./output/rejections.log

whitelist_file: ./australian_whitelist.json
brand_file: ./australian_indicators_merged.json

workers:
  max_workers: 10
  max_process_workers: 4
```

Feel free to add or remove feeds, adjust worker counts or change the output
paths.

