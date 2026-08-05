# Secure Clipboard

GNOME Shell extension: **secrets-aware clipboard** for the top panel — detect high-risk content, never store it, auto-clear after a timeout.

## Features

- Watches the clipboard (short poll interval)
- Classifies secrets (private keys, seed-like phrases, API tokens, JWTs, long hex keys, credential assignments, and similar)
- **Secrets are never stored** in history (redacted placeholder only)
- Auto-clear clipboard + primary selection after 30 seconds (default, toggleable)
- Short **in-memory** history for non-secret clips (session only; cleared on disable)
- Click a history row to re-copy

## Requirements

- GNOME Shell **45–50**

## Install (local)

```bash
UUID=secure-clipboard@n0l0g1c.github.io
mkdir -p ~/.local/share/gnome-shell/extensions
cp -a "$UUID" ~/.local/share/gnome-shell/extensions/
gnome-extensions enable "$UUID"
```

On Wayland, log out and back in so the shell discovers a newly copied UUID, then enable it.

## Clipboard access (EGO requirement)

This extension **reads the system clipboard** continuously while enabled in order to classify content. That access is declared in `metadata.json`.

- Clipboard data is **never** sent to any network service
- Secrets are **not** written to disk or to history text
- History lives in memory only and is wiped in `disable()`

Optional config: `~/.config/secure-clipboard/settings.json`

```json
{
  "autoClearSecrets": true,
  "clearSeconds": 30,
  "maxHistory": 20
}
```

## Limits

- Heuristics can false-positive (for example long hex strings or word lists). Prefer auto-clear for safety.
- This is not a full password manager and does not encrypt history.

## Publish to extensions.gnome.org

Follows the [EGO review guidelines](https://gjs.guide/extensions/review-guidelines/review-guidelines.html):

| Requirement | How this extension complies |
|---|---|
| GPL-compatible license | GPL-2.0-or-later (`LICENSE`) |
| Clipboard disclosure | Declared in description |
| No sharing clipboard with third parties | Local only |
| No default clipboard shortcuts | None shipped |
| Lifecycle | Timers and history cleared in `disable()` |
| No telemetry | None |
| Zip contents | Runtime files only (`./pack.sh`) |

### Package for upload

```bash
./pack.sh
# produces: secure-clipboard@n0l0g1c.github.io.shell-extension.zip
```

Upload at [extensions.gnome.org](https://extensions.gnome.org/).

## Development

```bash
cp -a secure-clipboard@n0l0g1c.github.io \
  ~/.local/share/gnome-shell/extensions/
journalctl -f /usr/bin/gnome-shell
```

## License

[GPL-2.0-or-later](LICENSE)

## Author

[N0L0g1c](https://github.com/N0L0g1c)
