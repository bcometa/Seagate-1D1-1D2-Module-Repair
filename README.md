# 1D1 Repair & Unlock

Internal [$300 Data Recovery](https://www.300dollardatarecovery.com) tool for inspecting and repairing Seagate Rosewood / M11 / SED firmware modules (`1D1`, `1D2`, `0x227`, `0x30A`). Reconstructs corrupted `1D2` modules from intact `1D1` or `0x227`, optionally applies the *"permanent ROM unlock"* patch (byte `0x04`: `0x80 → 0x81` with checksum fix), and carves the `0x30A` passwords module from either source.

All processing happens locally in the browser/Python session. No files are uploaded anywhere.

## Run locally

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Open <http://localhost:8501>.

## Run on Streamlit Community Cloud

1. Push this repo to GitHub.
2. Sign in at <https://share.streamlit.io> and point it at the repo.
3. Main file: `streamlit_app.py`.
4. **Set the password** under *Settings → Secrets*:
   ```toml
   password = "***"
   ```
   (See "Password" section below for the resolution order.)

## Password

The app is gated by a password screen. The expected value is resolved in this order:

1. `st.secrets["password"]` — set in `.streamlit/secrets.toml` locally, or via the *Secrets* UI on Streamlit Community Cloud. **Recommended for any deployment** so the value is not in the public repo.
2. `APP_PASSWORD` environment variable — useful for Docker / CI deployments.
3. The hardcoded `APP_PASSWORD_DEFAULT` constant at the top of `streamlit_app.py` — currently `"***"` for local development.

To override locally, create `.streamlit/secrets.toml` (already excluded by `.gitignore`):

```toml
password = "your-new-password"
```

## Usage

1. **Drop in module dumps** — up to six at once (`1D1×0`, `1D1×1`, `1D2×0`, `1D2×1`, `0x227`, `0x30A`), or a single `.zip` archive containing them. `.Bin` and `.rpm` extensions are both accepted. `.7z` is not supported in-browser; extract first or re-zip.
2. The tool **auto-classifies** by filename (looks for `1d1` / `1d2` / `227` / `30a` plus `x0` / `x1`) and falls back to size if the name is ambiguous. It also **auto-selects the healthier copy** of each module as the active source.
3. The **Inspection** panel shows a one-row-per-module summary, then a detailed comparison of the carved candidate against the supplied `1D2`, including:
   - Header magic, lock-byte state, checksum validity, capacity, sentinel, band-ID scan
   - **Key-region match diagnostic** — confirms whether the `1D2`'s encryption keys are intact or need restoring from source
   - Cross-checks between redundant copies and between modules
4. The **Repair operations** panel leads with up to two recommendations:
   - **Primary** — the safer minimal-change action (typically `Op A` *carve only, preserve lock state*)
   - **Alternate** — same with permanent ROM unlock applied (`Op B`)

   Click the labeled download button to get the resulting `.Bin` file. Eight detailed ops are listed below for advanced/manual cases.

## Operations

| Op | Source            | Output             | What it does                                                              |
|----|-------------------|--------------------|---------------------------------------------------------------------------|
| A  | `1D1`             | `1D2` (0x2000 B)   | Carve only — preserve original lock state                                 |
| B  | `1D1`             | `1D2` (0x2000 B)   | Carve + Permanent ROM Unlock (lock = `0x81`, checksum +1)                 |
| C  | existing `1D2`    | `1D2` (0x2000 B)   | Patch existing `1D2` with permanent unlock (no carve, keys untouched)     |
| D  | `1D1`             | `0x30A` partial    | Extract 0x110 bytes at offset `0x39000`                                   |
| E  | `1D1` + `1D2`     | `1D2`              | Basic unlock (jackass25 method, experimental — does NOT produce a valid header) |
| F  | `0x227`           | `1D2` (0x2000 B)   | Carve from `0x227` — preserve original lock state                         |
| G  | `0x227`           | `1D2` (0x2000 B)   | Carve from `0x227` + Permanent ROM Unlock                                 |
| H  | `0x227`           | `0x30A` full       | Extract 0x1000 bytes (4 KiB) at offset `0x2F1000`                         |

## Note on terminology

**"Permanent ROM unlock"** means the drive's terminal comes up unlocked at every power-on without sending a handshake. **It is not ATA-password unlock.** Encrypted user/master passwords in `0x30A` are unaffected, and per HDD Guru testing they cannot be transferred between donors because the encryption is salted per-drive.

## Module layout reference

| Field                            | Offset                | Notes                                                         |
|----------------------------------|-----------------------|---------------------------------------------------------------|
| `1D2` header magic               | `0x0000`              | `C2 BD 12 0B`                                                 |
| Lock-state byte                  | `0x04`                | `0x80` = locked · `0x81` = permanent ROM unlock · `0xFF` = blanked |
| Band-key region (16×128 B)       | `0x0100 – 0x0900`     | 96-byte AES key + band-ID + 0xFFFF terminator per record       |
| Band-key region duplicate        | `0x0980 – 0x1180`     | Redundant copy                                                |
| Drive sentinel                   | `0x1BE0`              | Per-drive byte (`0x01` on 1 TB, `0xE1` on 2/4 TB samples)     |
| Capacity (LBAs, LE uint64)       | `0x1C20`              |                                                               |
| Checksum (LE uint16)             | `0x1C88`              | Equals Σ uint16-LE words from `0x00` to `0x1C88`              |
| `1D2` inside `1D1`               | `0x22000 – 0x23FFF`   | 0x2000 bytes                                                  |
| `0x30A` partial inside `1D1`     | `0x39000 – 0x3910F`   | 0x110 bytes                                                   |
| `1D2` inside `0x227`             | `0x1C5000 – 0x1DBFFF` | 0x2000 bytes                                                  |
| `0x30A` inside `0x227`           | `0x2F1000 – 0x2F1FFF` | 0x1000 bytes (full)                                           |

## References

- HDD Guru forum thread on `0x1D2` carving and permanent ROM unlock procedure (`fzabkar`, `unknown`, `jackass25`, others)
- Seagate Enterprise SED User Guide ([100515636c.pdf](https://www.seagate.com/files/staticfiles/support/docs/manual/Interface%20manuals/100515636c.pdf)) — for band-record structure

## Disclaimer

This tool produces firmware-module images that can brick a drive if written back incorrectly. Always keep a backup of the original `1D1`, `1D2`, `0x227`, and `0x30A` modules before writing any of the tool's outputs back to the drive. Test on donor drives first.

## License

MIT (or specify your own).
