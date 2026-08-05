# Secure Clipboard

GNOME Shell extension that watches the clipboard for secrets, never stores them, and auto-clears after a timeout.

![Screenshot](screenshots/screenshot.png)

## Features

- Short-interval clipboard polling
- Detects private keys, seed-like phrases, API tokens, JWTs, long hex keys, credential assignments, and similar
- Secrets are never stored in history (redacted placeholder only)
- Auto-clear clipboard + primary selection (default 30s, toggleable)
- In-memory history for non-secret clips (session only)
- Click a history row to re-copy

## Requirements

- GNOME Shell **45–50**

## Install

```bash
UUID=secure-clipboard@n0l0g1c.github.io
mkdir -p ~/.local/share/gnome-shell/extensions
cp -a "$UUID" ~/.local/share/gnome-shell/extensions/
gnome-extensions enable "$UUID"
```

Log out/in on Wayland (or restart GNOME Shell) so the extension is picked up.

## Clipboard access

While enabled, the extension reads the system clipboard to classify content (declared in `metadata.json`).

- Nothing is sent over the network
- Secrets are not written to disk or history text
- History lives in memory and is wiped on disable

Optional config: `~/.config/secure-clipboard/settings.json`

```json
{
  "autoClearSecrets": true,
  "clearSeconds": 30,
  "maxHistory": 20
}
```

## Limits

- Heuristics can false-positive (long hex, word lists, etc.). Prefer auto-clear when in doubt.
- Not a password manager; history is not encrypted.

## Packaging

```bash
./pack.sh
# → secure-clipboard@n0l0g1c.github.io.shell-extension.zip
```

## License

[GPL-2.0-or-later](LICENSE)

## Author

[N0L0g1c](https://github.com/N0L0g1c)
