// SPDX-License-Identifier: GPL-2.0-or-later
/* watch clipboard, drop secrets after a delay */

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

function looksSecret(s) {
    const t = s.trim();
    if (!t)
        return null;
    if (/-----BEGIN .*PRIVATE KEY-----/.test(t))
        return 'private-key';
    if (/-----BEGIN PGP PRIVATE KEY BLOCK-----/.test(t))
        return 'pgp-key';
    if (/^(0x)?[a-fA-F0-9]{64}$/.test(t))
        return 'hex-key';
    if (/^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(t))
        return 'jwt';
    if (/\b(ghp_|github_pat_|glpat-|sk_live_|sk-)[A-Za-z0-9_\-]{16,}/.test(t))
        return 'token';
    const w = t.toLowerCase().split(/\s+/).filter(Boolean);
    if ([12, 15, 18, 21, 24].includes(w.length) && w.every(x => /^[a-z]{3,12}$/.test(x)))
        return 'seed';
    if (/\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*\S{8,}/i.test(t) && t.length < 400)
        return 'credential';
    return null;
}

const Button = GObject.registerClass(
class Button extends PanelMenu.Button {
    _init() {
        super._init(0.5, 'Secure Clipboard');

        this._lbl = new St.Label({
            text: 'Clip',
            y_expand: true,
            y_align: Clutter.ActorAlign.CENTER,
        });
        this.add_child(this._lbl);

        this.history = [];
        this.last = null;
        this.autoClear = true;
        this.clearSec = 30;
        this.clearSrc = 0;
        this.deadline = 0;
        this.clip = St.Clipboard.get_default();

        this.status = new PopupMenu.PopupMenuItem('watching clipboard', {reactive: false});
        this.menu.addMenuItem(this.status);
        this.countdown = new PopupMenu.PopupMenuItem('', {reactive: false});
        this.countdown.visible = false;
        this.menu.addMenuItem(this.countdown);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this.section = new PopupMenu.PopupMenuSection();
        this.menu.addMenuItem(this.section);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        let i = new PopupMenu.PopupMenuItem('Clear clipboard');
        i.connect('activate', () => this.clearNow(false));
        this.menu.addMenuItem(i);

        i = new PopupMenu.PopupMenuItem('Clear history');
        i.connect('activate', () => {
            this.history = [];
            this.rebuild();
        });
        this.menu.addMenuItem(i);

        this.toggle = new PopupMenu.PopupMenuItem(this.toggleLabel());
        this.toggle.connect('activate', () => {
            this.autoClear = !this.autoClear;
            this.toggle.label.text = this.toggleLabel();
            if (!this.autoClear)
                this.stopTimer();
        });
        this.menu.addMenuItem(this.toggle);

        this.rebuild();
        this._loadSettings();

        this.poll = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 400, () => {
            this.clip.get_text(St.ClipboardType.CLIPBOARD, (_c, text) => {
                if (text === null || text === this.last)
                    return;
                this.onText(text);
            });
            if (this.deadline) {
                const left = Math.ceil((this.deadline - Date.now()) / 1000);
                this.countdown.visible = true;
                this.countdown.label.text = left > 0
                    ? `clearing in ${left}s`
                    : 'clearing…';
            }
            return GLib.SOURCE_CONTINUE;
        });
    }

    toggleLabel() {
        return this.autoClear
            ? `auto-clear secrets (${this.clearSec}s)`
            : 'auto-clear secrets: off';
    }

    async _loadSettings() {
        try {
            const path = `${GLib.get_user_config_dir()}/secure-clipboard/settings.json`;
            const f = Gio.File.new_for_path(path);
            if (!f.query_exists(null))
                return;
            const [, b] = await f.load_contents_async(null);
            const j = JSON.parse(new TextDecoder().decode(b));
            if (j.autoClearSecrets === false)
                this.autoClear = false;
            if (j.clearSeconds)
                this.clearSec = Math.min(300, Math.max(5, Number(j.clearSeconds) || 30));
            this.toggle.label.text = this.toggleLabel();
        } catch (e) {
            // ignore bad config
        }
    }

    destroy() {
        if (this.poll) {
            GLib.Source.remove(this.poll);
            this.poll = 0;
        }
        this.stopTimer();
        this.history = [];
        this.clip = null;
        super.destroy();
    }

    onText(text) {
        this.last = text;
        if (!text || !text.trim()) {
            this.stopTimer();
            return;
        }
        const kind = looksSecret(text);
        if (kind) {
            this.history = this.history.filter(h => !h.secret);
            this.history.unshift({
                secret: true,
                kind,
                preview: `[secret] ${kind}`,
                text: '',
            });
            this._lbl.text = 'SECRET';
            this.status.label.text = `detected ${kind} (not stored)`;
            if (this.autoClear)
                this.armTimer();
            else
                this.stopTimer();
        } else {
            const preview = text.replace(/\s+/g, ' ').trim();
            this.history = this.history.filter(h => h.text !== text);
            this.history.unshift({
                secret: false,
                kind: 'text',
                preview: preview.length > 50 ? `${preview.slice(0, 50)}…` : preview,
                text,
            });
            if (this.history.length > 20)
                this.history.length = 20;
            this._lbl.text = 'Clip';
            this.status.label.text = 'captured';
            this.stopTimer();
        }
        this.rebuild();
    }

    armTimer() {
        this.stopTimer();
        this.deadline = Date.now() + this.clearSec * 1000;
        this.clearSrc = GLib.timeout_add_seconds(
            GLib.PRIORITY_DEFAULT, this.clearSec, () => {
                this.clearSrc = 0;
                this.clearNow(true);
                return GLib.SOURCE_REMOVE;
            });
    }

    stopTimer() {
        if (this.clearSrc) {
            GLib.Source.remove(this.clearSrc);
            this.clearSrc = 0;
        }
        this.deadline = 0;
        this.countdown.visible = false;
    }

    clearNow(notify) {
        if (!this.clip)
            return;
        this.clip.set_text(St.ClipboardType.CLIPBOARD, '');
        this.clip.set_text(St.ClipboardType.PRIMARY, '');
        this.last = '';
        this.stopTimer();
        this._lbl.text = 'Cleared';
        this.status.label.text = notify ? 'secret cleared' : 'cleared';
        this.history = this.history.filter(h => !h.secret);
        this.rebuild();
        if (notify)
            Main.notify('Secure Clipboard', 'Secret removed from clipboard');
    }

    rebuild() {
        this.section.removeAll();
        if (!this.history.length) {
            this.section.addMenuItem(
                new PopupMenu.PopupMenuItem('(empty)', {reactive: false}));
            return;
        }
        for (const h of this.history) {
            const item = new PopupMenu.PopupMenuItem(h.preview, {
                reactive: !h.secret,
            });
            item.label.clutter_text.ellipsize = Pango.EllipsizeMode.END;
            if (!h.secret) {
                item.connect('activate', () => {
                    this.clip.set_text(St.ClipboardType.CLIPBOARD, h.text);
                    this.last = h.text;
                    this.status.label.text = 're-copied';
                });
            }
            this.section.addMenuItem(item);
        }
    }
});

export default class extends Extension {
    enable() {
        this._indicator = new Button();
        Main.panel.addToStatusArea(this.uuid, this._indicator);
    }

    disable() {
        this._indicator.destroy();
        this._indicator = null;
    }
}
