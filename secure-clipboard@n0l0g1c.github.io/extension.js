// Secure Clipboard — secrets-aware clipboard with auto-clear + redacted history
// SPDX-License-Identifier: GPL-2.0-or-later

import Clutter from 'gi://Clutter';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import Gio from 'gi://Gio';
import Pango from 'gi://Pango';
import St from 'gi://St';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';

Gio._promisify(Gio.File.prototype, 'load_contents_async', 'load_contents_finish');

const POLL_MS = 500;
const MAX_HISTORY = 20;
const CONFIG_DIR = 'secure-clipboard';
const CONFIG_FILE = 'settings.json';

function defaultConfig() {
    return {
        autoClearSecrets: true,
        clearSeconds: 30,
        maxHistory: MAX_HISTORY,
    };
}

async function loadConfig() {
    const defaults = defaultConfig();
    try {
        const path = GLib.build_filenamev([
            GLib.get_user_config_dir(),
            CONFIG_DIR,
            CONFIG_FILE,
        ]);
        const file = Gio.File.new_for_path(path);
        if (!file.query_exists(null))
            return defaults;
        const [, bytes] = await file.load_contents_async(null);
        const data = JSON.parse(new TextDecoder().decode(bytes));
        return {
            autoClearSecrets: data.autoClearSecrets !== false,
            clearSeconds: Math.max(5, Math.min(300, Number(data.clearSeconds) || 30)),
            maxHistory: Math.max(5, Math.min(50, Number(data.maxHistory) || MAX_HISTORY)),
        };
    } catch {
        return defaults;
    }
}

function classify(text) {
    if (!text)
        return {secret: false, kind: 'empty'};

    const t = text.trim();

    if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/.test(t))
        return {secret: true, kind: 'private-key'};

    if (/-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(t))
        return {secret: true, kind: 'pgp-key'};

    // bare 64-char hex (optional 0x) — common for eth/private keys
    if (/^(?:0x)?[a-fA-F0-9]{64}$/.test(t))
        return {secret: true, kind: 'hex-key'};

    // rough BIP39: 12–24 lowercase words
    const words = t.toLowerCase().split(/\s+/).filter(Boolean);
    if ([12, 15, 18, 21, 24].includes(words.length) &&
        words.every(w => /^[a-z]+$/.test(w) && w.length >= 3 && w.length <= 12))
        return {secret: true, kind: 'seed-phrase'};

    if (/\bAKIA[0-9A-Z]{16}\b/.test(t))
        return {secret: true, kind: 'aws-key-id'};
    if (/\b(?:aws)?_?secret_?access_?key\b\s*[:=]\s*\S{20,}/i.test(t))
        return {secret: true, kind: 'aws-secret'};

    if (/\bghp_[A-Za-z0-9]{20,}\b/.test(t) ||
        /\bgithub_pat_[A-Za-z0-9_]{20,}\b/.test(t) ||
        /\bglpat-[A-Za-z0-9\-_]{20,}\b/.test(t))
        return {secret: true, kind: 'api-token'};

    if (/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/.test(t) ||
        /\bsk_live_[A-Za-z0-9]{20,}\b/.test(t) ||
        /\bsk-[A-Za-z0-9]{32,}\b/.test(t))
        return {secret: true, kind: 'api-token'};

    if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(t))
        return {secret: true, kind: 'jwt'};

    // long compact base64-looking blob
    if (t.length >= 80 && t.length <= 4096 &&
        /^[A-Za-z0-9+/=\s]+$/.test(t) &&
        (t.match(/[A-Za-z0-9+/=]/g) || []).length >= 64 &&
        !/\s{2,}/.test(t.slice(0, 40))) {
        if (!/\s/.test(t) || t.split(/\s+/).length <= 3)
            return {secret: true, kind: 'base64-secret'};
    }

    if (/\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S{8,}/i.test(t) &&
        t.length < 500)
        return {secret: true, kind: 'credential'};

    return {secret: false, kind: 'text'};
}

function makePreview(text, secret, kind) {
    if (secret)
        return `🔒 ${kind} (hidden · will auto-clear)`;
    const one = text.replace(/\s+/g, ' ').trim();
    if (one.length <= 56)
        return one;
    return `${one.slice(0, 53)}…`;
}

class HistoryRow extends PopupMenu.PopupBaseMenuItem {
    static {
        GObject.registerClass(this);
    }

    constructor(entry, onActivate) {
        super({
            reactive: !entry.secret,
            can_focus: !entry.secret,
            style_class: 'sc-row',
        });

        const preview = new St.Label({
            text: entry.preview,
            y_align: Clutter.ActorAlign.CENTER,
            style_class: entry.secret ? 'sc-preview sc-secret' : 'sc-preview',
            x_expand: true,
        });
        preview.clutter_text.ellipsize = Pango.EllipsizeMode.END;
        this.add_child(preview);

        const age = new St.Label({
            text: entry.kind,
            y_align: Clutter.ActorAlign.CENTER,
            style_class: 'sc-meta',
        });
        this.add_child(age);

        if (!entry.secret)
            this.connect('activate', () => onActivate(entry));
    }
}

class SecureClipboardIndicator extends PanelMenu.Button {
    static {
        GObject.registerClass(this);
    }

    constructor() {
        super(0.5, 'Secure Clipboard', false);

        const box = new St.BoxLayout({
            style_class: 'panel-status-menu-box',
        });

        this._panelIcon = new St.Icon({
            icon_name: 'edit-paste-symbolic',
            style_class: 'system-status-icon',
        });
        box.add_child(this._panelIcon);

        this._panelLabel = new St.Label({
            text: 'Clip',
            y_align: Clutter.ActorAlign.CENTER,
            style_class: 'sc-panel-label',
        });
        box.add_child(this._panelLabel);

        this.add_child(box);

        this._cfg = defaultConfig();
        this._history = [];
        this._lastText = null;
        this._nextId = 1;
        this._pollSource = 0;
        this._clearSource = 0;
        this._clearDeadline = 0;
        this._countdownSource = 0;
        this._currentSecret = false;
        this._clipboard = St.Clipboard.get_default();

        this._statusItem = new PopupMenu.PopupMenuItem('Watching clipboard…', {
            reactive: false,
            can_focus: false,
        });
        this._statusItem.label.add_style_class_name('sc-status');
        this.menu.addMenuItem(this._statusItem);

        this._countdownItem = new PopupMenu.PopupMenuItem(' ', {
            reactive: false,
            can_focus: false,
        });
        this._countdownItem.label.add_style_class_name('sc-countdown sc-danger');
        this.menu.addMenuItem(this._countdownItem);
        this._countdownItem.visible = false;

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._listSection = new PopupMenu.PopupMenuSection();
        const scrollView = new St.ScrollView({
            style_class: 'vfade sc-scroll',
            overlay_scrollbars: true,
            x_expand: true,
            child: this._listSection.box,
        });
        scrollView._delegate = this._listSection;
        this._listSection.actor = scrollView;
        this.menu.addMenuItem(this._listSection);

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._clearNowItem = new PopupMenu.PopupMenuItem('Clear clipboard now');
        this._clearNowItem.connect('activate', () => this._clearClipboard('manual'));
        this.menu.addMenuItem(this._clearNowItem);

        this._clearHistItem = new PopupMenu.PopupMenuItem('Clear history');
        this._clearHistItem.connect('activate', () => {
            this._history = [];
            this._rebuildHistory();
            this._statusItem.label.text = 'History cleared';
        });
        this.menu.addMenuItem(this._clearHistItem);

        this._toggleClearItem = new PopupMenu.PopupMenuItem(this._toggleClearLabel());
        this._toggleClearItem.connect('activate', () => {
            this._cfg.autoClearSecrets = !this._cfg.autoClearSecrets;
            this._toggleClearItem.label.text = this._toggleClearLabel();
            this._statusItem.label.text = this._cfg.autoClearSecrets
                ? 'Auto-clear secrets: ON'
                : 'Auto-clear secrets: OFF';
        });
        this.menu.addMenuItem(this._toggleClearItem);

        const hint = new PopupMenu.PopupMenuItem(
            'Secrets are never stored. Click a row to re-copy.',
            {reactive: false, can_focus: false}
        );
        hint.label.add_style_class_name('sc-hint');
        this.menu.addMenuItem(hint);

        this._rebuildHistory();
    }

    _toggleClearLabel() {
        return this._cfg.autoClearSecrets
            ? `Auto-clear secrets: ON (${this._cfg.clearSeconds}s)`
            : 'Auto-clear secrets: OFF';
    }

    async start() {
        this._cfg = await loadConfig();
        this._toggleClearItem.label.text = this._toggleClearLabel();
        this._pollSource = GLib.timeout_add(GLib.PRIORITY_DEFAULT, POLL_MS, () => {
            this._pollClipboard();
            return GLib.SOURCE_CONTINUE;
        });
        this._countdownSource = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 500, () => {
            this._updateCountdown();
            return GLib.SOURCE_CONTINUE;
        });
    }

    destroy() {
        for (const key of ['_pollSource', '_clearSource', '_countdownSource']) {
            if (this[key]) {
                try {
                    GLib.Source.remove(this[key]);
                } catch {
                    // already gone
                }
                this[key] = 0;
            }
        }
        this._history = [];
        this._lastText = null;
        this._clipboard = null;
        super.destroy();
    }

    _pollClipboard() {
        if (!this._clipboard)
            return;
        this._clipboard.get_text(St.ClipboardType.CLIPBOARD, (_clip, text) => {
            if (text === null || text === undefined)
                return;
            if (text === this._lastText)
                return;
            this._onNewClipboard(text);
        });
    }

    _onNewClipboard(text) {
        this._lastText = text;

        if (!text || !text.trim()) {
            this._currentSecret = false;
            this._cancelClear();
            return;
        }

        const {secret, kind} = classify(text);
        this._currentSecret = secret;

        const entry = {
            id: this._nextId++,
            preview: makePreview(text, secret, kind),
            // secrets never land in history text
            text: secret ? '' : text,
            secret,
            kind,
            at: Date.now(),
        };

        if (secret) {
            this._history = this._history.filter(h => !h.secret);
            this._history.unshift(entry);
            this._panelLabel.text = 'SECRET';
            this._panelLabel.style_class = 'sc-panel-label sc-danger';
            this._panelIcon.icon_name = 'security-high-symbolic';
            this._statusItem.label.text = `Detected ${kind} — not stored`;

            if (this._cfg.autoClearSecrets)
                this._scheduleClear(this._cfg.clearSeconds * 1000);
            else
                this._cancelClear();
        } else {
            this._history = this._history.filter(h => h.text !== text);
            this._history.unshift(entry);
            if (this._history.length > this._cfg.maxHistory)
                this._history.length = this._cfg.maxHistory;

            this._panelLabel.text = 'Clip';
            this._panelLabel.style_class = 'sc-panel-label sc-ok';
            this._panelIcon.icon_name = 'edit-paste-symbolic';
            this._statusItem.label.text = `Captured · ${kind}`;
            this._cancelClear();
            this._currentSecret = false;
        }

        this._rebuildHistory();
    }

    _scheduleClear(ms) {
        this._cancelClear();
        this._clearDeadline = Date.now() + ms;
        this._countdownItem.visible = true;
        this._updateCountdown();
        this._clearSource = GLib.timeout_add(GLib.PRIORITY_DEFAULT, ms, () => {
            this._clearSource = 0;
            this._clearClipboard('auto');
            return GLib.SOURCE_REMOVE;
        });
    }

    _cancelClear() {
        if (this._clearSource) {
            try {
                GLib.Source.remove(this._clearSource);
            } catch {
                // already gone
            }
            this._clearSource = 0;
        }
        this._clearDeadline = 0;
        this._countdownItem.visible = false;
        this._countdownItem.label.text = ' ';
    }

    _updateCountdown() {
        if (!this._clearDeadline) {
            this._countdownItem.visible = false;
            return;
        }
        const left = Math.max(0, Math.ceil((this._clearDeadline - Date.now()) / 1000));
        this._countdownItem.visible = true;
        this._countdownItem.label.text = `Clearing secret in ${left}s…`;
        if (left <= 0 && this._currentSecret)
            this._countdownItem.label.text = 'Clearing…';
    }

    _clearClipboard(reason) {
        if (!this._clipboard)
            return;
        this._clipboard.set_text(St.ClipboardType.CLIPBOARD, '');
        try {
            this._clipboard.set_text(St.ClipboardType.PRIMARY, '');
        } catch {
            // primary selection optional
        }
        this._lastText = '';
        this._currentSecret = false;
        this._cancelClear();
        this._panelLabel.text = 'Cleared';
        this._panelLabel.style_class = 'sc-panel-label sc-ok';
        this._panelIcon.icon_name = 'edit-clear-symbolic';
        this._statusItem.label.text = reason === 'auto'
            ? 'Secret auto-cleared from clipboard'
            : 'Clipboard cleared';

        this._history = this._history.filter(h => !h.secret);
        this._rebuildHistory();

        if (reason === 'auto')
            Main.notify('Secure Clipboard', 'Sensitive clipboard content cleared');
    }

    _rebuildHistory() {
        this._listSection.removeAll();
        if (this._history.length === 0) {
            const empty = new PopupMenu.PopupMenuItem('No history yet', {
                reactive: false,
                can_focus: false,
            });
            empty.label.add_style_class_name('sc-hint');
            this._listSection.addMenuItem(empty);
            return;
        }
        for (const entry of this._history)
            this._listSection.addMenuItem(new HistoryRow(entry, e => this._recopy(e)));
    }

    _recopy(entry) {
        if (entry.secret || !entry.text)
            return;
        this._clipboard.set_text(St.ClipboardType.CLIPBOARD, entry.text);
        this._lastText = entry.text;
        this._statusItem.label.text = 'Re-copied from history';
        Main.notify('Secure Clipboard', 'Copied from history');
    }
}

export default class SecureClipboardExtension extends Extension {
    _addToPanel(role, indicator) {
        const existing = Main.panel.statusArea[role];
        if (existing) {
            try {
                existing.destroy();
            } catch {
                // ignore
            }
            if (Main.panel.statusArea[role])
                delete Main.panel.statusArea[role];
        }
        Main.panel.addToStatusArea(role, indicator);
    }

    enable() {
        this._indicator = new SecureClipboardIndicator();
        this._addToPanel(this.uuid, this._indicator);
        this._indicator.start().catch(e => logError(e));
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
    }
}
