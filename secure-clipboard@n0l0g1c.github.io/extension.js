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

function classify(text) {
    if (!text)
        return {secret: false, kind: 'empty'};
    const t = text.trim();

    if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/.test(t))
        return {secret: true, kind: 'private-key'};
    if (/-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(t))
        return {secret: true, kind: 'pgp-key'};
    if (/^(?:0x)?[a-fA-F0-9]{64}$/.test(t))
        return {secret: true, kind: 'hex-key'};

    const words = t.toLowerCase().split(/\s+/).filter(Boolean);
    if ([12, 15, 18, 21, 24].includes(words.length) &&
        words.every(w => /^[a-z]{3,12}$/.test(w)))
        return {secret: true, kind: 'seed-phrase'};

    if (/\b(ghp_|github_pat_|glpat-|sk_live_|sk-|xox[baprs]-)[A-Za-z0-9_\-]{10,}/.test(t))
        return {secret: true, kind: 'api-token'};
    if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(t))
        return {secret: true, kind: 'jwt'};
    if (/\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S{8,}/i.test(t) &&
        t.length < 500)
        return {secret: true, kind: 'credential'};

    return {secret: false, kind: 'text'};
}

function preview(text, secret, kind) {
    if (secret)
        return `[secret] ${kind}`;
    const one = text.replace(/\s+/g, ' ').trim();
    return one.length <= 56 ? one : `${one.slice(0, 53)}…`;
}

class HistoryRow extends PopupMenu.PopupBaseMenuItem {
    static { GObject.registerClass(this); }

    constructor(entry, onActivate) {
        super({
            reactive: !entry.secret,
            can_focus: !entry.secret,
            style_class: 'sc-row',
        });
        const label = new St.Label({
            text: entry.preview,
            y_align: Clutter.ActorAlign.CENTER,
            style_class: entry.secret ? 'sc-preview sc-secret' : 'sc-preview',
            x_expand: true,
        });
        label.clutter_text.ellipsize = Pango.EllipsizeMode.END;
        this.add_child(label);
        this.add_child(new St.Label({
            text: entry.kind,
            y_align: Clutter.ActorAlign.CENTER,
            style_class: 'sc-meta',
        }));
        if (!entry.secret)
            this.connect('activate', () => onActivate(entry));
    }
}

class Indicator extends PanelMenu.Button {
    static { GObject.registerClass(this); }

    constructor() {
        super(0.5, 'Secure Clipboard', false);

        const box = new St.BoxLayout({style_class: 'panel-status-menu-box'});
        this._icon = new St.Icon({
            icon_name: 'edit-paste-symbolic',
            style_class: 'system-status-icon',
        });
        this._label = new St.Label({
            text: 'Clip',
            y_align: Clutter.ActorAlign.CENTER,
            style_class: 'sc-panel-label',
        });
        box.add_child(this._icon);
        box.add_child(this._label);
        this.add_child(box);

        this._autoClear = true;
        this._clearSeconds = 30;
        this._maxHistory = MAX_HISTORY;
        this._history = [];
        this._last = null;
        this._poll = 0;
        this._clearTimer = 0;
        this._tick = 0;
        this._deadline = 0;
        this._holdingSecret = false;
        this._clip = St.Clipboard.get_default();

        this._status = new PopupMenu.PopupMenuItem('Watching…', {
            reactive: false, can_focus: false,
        });
        this._status.label.add_style_class_name('sc-status');
        this.menu.addMenuItem(this._status);

        this._countdown = new PopupMenu.PopupMenuItem(' ', {
            reactive: false, can_focus: false,
        });
        this._countdown.label.add_style_class_name('sc-countdown sc-danger');
        this._countdown.visible = false;
        this.menu.addMenuItem(this._countdown);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._list = new PopupMenu.PopupMenuSection();
        const scroll = new St.ScrollView({
            style_class: 'vfade sc-scroll',
            overlay_scrollbars: true,
            x_expand: true,
            child: this._list.box,
        });
        scroll._delegate = this._list;
        this._list.actor = scroll;
        this.menu.addMenuItem(this._list);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        const clearNow = new PopupMenu.PopupMenuItem('Clear clipboard now');
        clearNow.connect('activate', () => this._wipe('manual'));
        this.menu.addMenuItem(clearNow);

        const clearHist = new PopupMenu.PopupMenuItem('Clear history');
        clearHist.connect('activate', () => {
            this._history = [];
            this._rebuild();
            this._status.label.text = 'History cleared';
        });
        this.menu.addMenuItem(clearHist);

        this._toggle = new PopupMenu.PopupMenuItem(this._toggleText());
        this._toggle.connect('activate', () => {
            this._autoClear = !this._autoClear;
            this._toggle.label.text = this._toggleText();
        });
        this.menu.addMenuItem(this._toggle);

        this._rebuild();
    }

    _toggleText() {
        return this._autoClear
            ? `Auto-clear secrets: ON (${this._clearSeconds}s)`
            : 'Auto-clear secrets: OFF';
    }

    async start() {
        try {
            const path = GLib.build_filenamev([
                GLib.get_user_config_dir(), 'secure-clipboard', 'settings.json',
            ]);
            const file = Gio.File.new_for_path(path);
            if (file.query_exists(null)) {
                const [, bytes] = await file.load_contents_async(null);
                const data = JSON.parse(new TextDecoder().decode(bytes));
                if (data.autoClearSecrets === false)
                    this._autoClear = false;
                if (data.clearSeconds)
                    this._clearSeconds = Math.max(5, Math.min(300, Number(data.clearSeconds)));
                if (data.maxHistory)
                    this._maxHistory = Math.max(5, Math.min(50, Number(data.maxHistory)));
                this._toggle.label.text = this._toggleText();
            }
        } catch {
            // defaults
        }

        this._poll = GLib.timeout_add(GLib.PRIORITY_DEFAULT, POLL_MS, () => {
            this._clip.get_text(St.ClipboardType.CLIPBOARD, (_c, text) => {
                if (text == null || text === this._last)
                    return;
                this._onClip(text);
            });
            return GLib.SOURCE_CONTINUE;
        });
        this._tick = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 500, () => {
            if (!this._deadline) {
                this._countdown.visible = false;
                return GLib.SOURCE_CONTINUE;
            }
            const left = Math.max(0, Math.ceil((this._deadline - Date.now()) / 1000));
            this._countdown.visible = true;
            this._countdown.label.text = left > 0
                ? `Clearing secret in ${left}s…`
                : 'Clearing…';
            return GLib.SOURCE_CONTINUE;
        });
    }

    destroy() {
        if (this._poll) {
            GLib.Source.remove(this._poll);
            this._poll = 0;
        }
        if (this._clearTimer) {
            GLib.Source.remove(this._clearTimer);
            this._clearTimer = 0;
        }
        if (this._tick) {
            GLib.Source.remove(this._tick);
            this._tick = 0;
        }
        this._history = [];
        this._clip = null;
        super.destroy();
    }

    _onClip(text) {
        this._last = text;
        if (!text || !text.trim()) {
            this._holdingSecret = false;
            this._stopClear();
            return;
        }

        const {secret, kind} = classify(text);
        this._holdingSecret = secret;
        const entry = {
            preview: preview(text, secret, kind),
            text: secret ? '' : text,
            secret,
            kind,
        };

        if (secret) {
            this._history = this._history.filter(h => !h.secret);
            this._history.unshift(entry);
            this._label.text = 'SECRET';
            this._label.style_class = 'sc-panel-label sc-danger';
            this._icon.icon_name = 'security-high-symbolic';
            this._status.label.text = `Detected ${kind} — not stored`;
            if (this._autoClear)
                this._armClear(this._clearSeconds * 1000);
            else
                this._stopClear();
        } else {
            this._history = this._history.filter(h => h.text !== text);
            this._history.unshift(entry);
            if (this._history.length > this._maxHistory)
                this._history.length = this._maxHistory;
            this._label.text = 'Clip';
            this._label.style_class = 'sc-panel-label sc-ok';
            this._icon.icon_name = 'edit-paste-symbolic';
            this._status.label.text = `Captured · ${kind}`;
            this._stopClear();
            this._holdingSecret = false;
        }
        this._rebuild();
    }

    _armClear(ms) {
        this._stopClear();
        this._deadline = Date.now() + ms;
        this._clearTimer = GLib.timeout_add(GLib.PRIORITY_DEFAULT, ms, () => {
            this._clearTimer = 0;
            this._wipe('auto');
            return GLib.SOURCE_REMOVE;
        });
    }

    _stopClear() {
        if (this._clearTimer) {
            GLib.Source.remove(this._clearTimer);
            this._clearTimer = 0;
        }
        this._deadline = 0;
        this._countdown.visible = false;
    }

    _wipe(reason) {
        if (!this._clip)
            return;
        this._clip.set_text(St.ClipboardType.CLIPBOARD, '');
        this._clip.set_text(St.ClipboardType.PRIMARY, '');
        this._last = '';
        this._holdingSecret = false;
        this._stopClear();
        this._label.text = 'Cleared';
        this._label.style_class = 'sc-panel-label sc-ok';
        this._icon.icon_name = 'edit-clear-symbolic';
        this._status.label.text = reason === 'auto'
            ? 'Secret auto-cleared'
            : 'Clipboard cleared';
        this._history = this._history.filter(h => !h.secret);
        this._rebuild();
        if (reason === 'auto')
            Main.notify('Secure Clipboard', 'Sensitive clipboard content cleared');
    }

    _rebuild() {
        this._list.removeAll();
        if (!this._history.length) {
            const empty = new PopupMenu.PopupMenuItem('No history yet', {
                reactive: false, can_focus: false,
            });
            empty.label.add_style_class_name('sc-hint');
            this._list.addMenuItem(empty);
            return;
        }
        for (const entry of this._history)
            this._list.addMenuItem(new HistoryRow(entry, e => this._recopy(e)));
    }

    _recopy(entry) {
        if (entry.secret || !entry.text)
            return;
        this._clip.set_text(St.ClipboardType.CLIPBOARD, entry.text);
        this._last = entry.text;
        this._status.label.text = 'Re-copied from history';
    }
}

export default class SecureClipboardExtension extends Extension {
    enable() {
        this._indicator = new Indicator();
        Main.panel.addToStatusArea(this.uuid, this._indicator);
        this._indicator.start().catch(e => logError(e));
    }

    disable() {
        this._indicator.destroy();
        this._indicator = null;
    }
}
