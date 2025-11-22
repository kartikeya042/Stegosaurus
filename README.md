# Stegosaurus — S-DES, RSA & Steganography (GUI)

Lightweight educational toolkit combining:

- Simplified DES (S-DES) — educational 8-bit block cipher with a 10-bit key
- RSA asymmetric encryption (via PyCryptodome)
- Image steganography (hide/extract bytes in PNG images)
- Hybrid mode: S-DES for data + RSA to encrypt the S-DES key
- Simple Tkinter GUI wrapper around the CLI utilities in `Test.py`

This repository contains a small GUI (`gui.py`) and the underlying utilities in `Test.py`. It is intended for learning and demonstration only — do not use the simplified cipher for real-world security.

**Requirements**

- Python 3.8+ (should work on 3.8, 3.9, 3.10, 3.11)
- See `requirements.txt` for required packages (`pycryptodome`, `Pillow`).

**Quick Start (Windows `cmd`)**

1. Create and/or activate a virtual environment (recommended):

```bat
python -m venv .venv
.venv\Scripts\activate
```

2. Install dependencies:

```bat
python -m pip install -r requirements.txt
```

3. Run the GUI:

```bat
python gui.py
```

Or run the original CLI menu application:

```bat
python Test.py
```

**What the GUI does**

- Generate RSA keypair (`private.pem`, `public.pem`).
- S-DES encrypt/decrypt text (save/load key and ciphertext files).
- RSA encrypt/decrypt short messages (uses RSA PKCS1 OAEP).
- Hide arbitrary text/bytes inside an image (`encoded.png`, PNG recommended).
- Extract embedded data from an image and save to `extracted_payload.bin`.
- Hybrid mode: encrypt data with S-DES, encrypt the S-DES key with RSA.

**Files of interest**

- `Test.py` — core implementations for S-DES, RSA helpers, steganography, and a CLI menu.
- `gui.py` — Tkinter GUI wrapping `Test.py` functions with file dialogs and output pane.
- `requirements.txt` — Python dependencies.

**Important security notes**

- S-DES in this project is intentionally simplified and NOT secure for any production use. It exists purely for education and demonstration.
- RSA keys are stored unencrypted as `private.pem`/`public.pem` in the working directory when generated; protect these files appropriately.

**Usage tips**

- When hiding data in an image, prefer a reasonably large PNG so there is enough capacity.
- The GUI will prompt to save key/ciphertext files; keep the S-DES key blob (`.key`) safe if you wish to decrypt later.

**Contributing**

Contributions are welcome — please open issues for bugs or feature requests. If you submit a PR, keep changes small and documented.

**License**

This repository is provided for educational purposes. You can add a proper license (for example, MIT) by creating a `LICENSE` file.

---

If you'd like, I can also:

- Add a sample image and example inputs to `examples/`.
- Add a proper `LICENSE` file (MIT/Apache) and a short `CONTRIBUTING.md`.
- Run a quick smoke test script to validate imports and basic operations.
