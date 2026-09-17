// Wormhole — a floating always-on-top paste box for an Event Horizon server.
//
// It mirrors the web app's "Wormhole" text box: type here and it syncs to the
// server's /api/clipboard; Copy puts the text on the macOS clipboard; Singularity
// shreds it on the server. Supports sealed (E2EE) sessions: it derives the key
// with PBKDF2(600k, SHA-256), verifies via SHA-256(key), and encrypts/decrypts
// with AES-256-GCM in the same IV‖ciphertext‖tag format the web app uses.
//
// AppKit, top-level code (no @main). Build with build.sh.

import AppKit
import CryptoKit
import CommonCrypto
import ServiceManagement

// MARK: - Persistence keys

private let kServerURL = "serverURL"
private let kCachedText = "cachedText"
private let kWindowAutosave = "WormholeWindow"

// MARK: - Crypto (wire-compatible with frontend/src/lib/crypto.js)

enum Crypto {
    /// PBKDF2-HMAC-SHA256, 600k iterations, 32-byte key.
    static func deriveKey(password: String, salt: Data) -> Data? {
        guard !password.isEmpty, !salt.isEmpty else { return nil }
        let keyLength = 32
        var derived = Data(repeating: 0, count: keyLength)
        let pw = Data(password.utf8)
        let status: Int32 = derived.withUnsafeMutableBytes { dPtr in
            pw.withUnsafeBytes { pPtr in
                salt.withUnsafeBytes { sPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pPtr.baseAddress!.assumingMemoryBound(to: CChar.self), pw.count,
                        sPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(600_000),
                        dPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), keyLength
                    )
                }
            }
        }
        return status == Int32(kCCSuccess) ? derived : nil // CCCryptorStatus is Int32; kCCSuccess imports as Int
    }

    static func keyHash(_ key: Data) -> Data { Data(SHA256.hash(data: key)) }

    /// Returns IV(12)‖ciphertext‖tag(16), matching WebCrypto AES-GCM output.
    static func encrypt(key: Data, plaintext: Data) -> Data? {
        guard let sealed = try? AES.GCM.seal(plaintext, using: SymmetricKey(data: key)) else { return nil }
        return sealed.combined // nonce(12) ‖ ciphertext ‖ tag(16)
    }

    static func decrypt(key: Data, blob: Data) -> Data? {
        guard let box = try? AES.GCM.SealedBox(combined: blob),
              let pt = try? AES.GCM.open(box, using: SymmetricKey(data: key)) else { return nil }
        return pt
    }
}

// MARK: - Networking (trusts the configured host's self-signed cert)

final class Net: NSObject, URLSessionDelegate {
    static let shared = Net()
    private lazy var session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 8
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }()

    // Accept the server's TLS certificate even if self-signed (LAN use).
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }

    struct Response { let status: Int; let json: [String: Any]?; let data: Data? }

    /// Builds an Origin header ("scheme://host[:port]") that matches the Host
    /// header URLSession sends — the default port (443/80) is omitted so the
    /// server's same-origin comparison (originHost == r.Host) succeeds.
    static func originHeader(for url: URL) -> String {
        let scheme = url.scheme ?? "https"
        let host = url.host ?? ""
        var origin = scheme + "://" + host
        if let port = url.port,
           !((scheme == "https" && port == 443) || (scheme == "http" && port == 80)) {
            origin += ":\(port)"
        }
        return origin
    }

    /// Fires a request; the completion runs on the main thread.
    func request(_ url: URL, method: String = "GET", token: String? = nil,
                 body: [String: Any]? = nil, done: @escaping (Response?) -> Void) {
        var req = URLRequest(url: url)
        req.httpMethod = method
        // The server enforces same-origin on state-changing /api requests (CSRF
        // protection, fail-closed on a missing Origin). Send an Origin that matches
        // the Host header URLSession will send (default ports omitted), so the box
        // is treated as same-origin.
        req.setValue(Net.originHeader(for: url), forHTTPHeaderField: "Origin")
        if let token = token { req.setValue(token, forHTTPHeaderField: "X-Session-Token") }
        if let body = body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        }
        session.dataTask(with: req) { data, resp, _ in
            let status = (resp as? HTTPURLResponse)?.statusCode ?? -1
            var json: [String: Any]? = nil
            if let d = data, let obj = try? JSONSerialization.jsonObject(with: d), let dict = obj as? [String: Any] {
                json = dict
            }
            DispatchQueue.main.async { done(status == -1 ? nil : Response(status: status, json: json, data: data)) }
        }.resume()
    }
}

// MARK: - Borderless window that can still take keyboard focus

final class KeyWindow: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}

// MARK: - App

final class AppController: NSObject, NSApplicationDelegate, NSTextViewDelegate {

    // UI
    private var window: KeyWindow!
    private var textView: NSTextView!
    private var statusLabel: NSTextField!
    private var statusItem: NSStatusItem!
    private var loginItem: NSMenuItem?

    // Config / session state
    private var serverURL: String { UserDefaults.standard.string(forKey: kServerURL) ?? "" }
    private var token: String?
    private var key: Data?               // present only when a sealed session is unlocked
    private var sealed = false           // last known: is the server session locked?
    private var promptedThisLock = false // avoid re-prompting for the password every poll

    // Sync bookkeeping
    private var lastServerText = ""
    private var suppressRemoteUntil = Date.distantPast
    private var applyingRemote = false
    private var saveWork: DispatchWorkItem?
    private var pollTimer: Timer?

    // MARK: Lifecycle

    func applicationDidFinishLaunching(_ note: Notification) {
        buildMenu()
        buildStatusItem()
        buildWindow()

        // Show cached text immediately so the box isn't empty on launch.
        let cached = UserDefaults.standard.string(forKey: kCachedText) ?? ""
        setText(cached, remote: false)
        lastServerText = cached

        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)

        if serverURL.isEmpty {
            setStatus("Set a server URL from the 🌀 menu")
        } else {
            refresh()
        }
        pollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    // MARK: Window & views

    private func buildWindow() {
        let frame = NSRect(x: 0, y: 0, width: 340, height: 260)
        window = KeyWindow(contentRect: frame,
                           styleMask: [.borderless, .resizable],
                           backing: .buffered, defer: false)
        window.level = .floating
        window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        window.isMovableByWindowBackground = true
        window.hasShadow = true
        window.minSize = NSSize(width: 220, height: 140)
        window.backgroundColor = NSColor(calibratedWhite: 0.08, alpha: 1.0)
        window.setFrameAutosaveName(kWindowAutosave)
        if !UserDefaults.standard.bool(forKey: "hasLaunched") {
            window.center()
            UserDefaults.standard.set(true, forKey: "hasLaunched")
        }

        let content = NSView(frame: frame)
        content.wantsLayer = true
        content.layer?.cornerRadius = 10
        content.layer?.masksToBounds = true
        content.layer?.backgroundColor = NSColor(calibratedWhite: 0.08, alpha: 1.0).cgColor
        window.contentView = content

        // Header (drag area) with the two action buttons.
        let header = NSView(frame: NSRect(x: 0, y: frame.height - 34, width: frame.width, height: 34))
        header.autoresizingMask = [.width, .minYMargin]
        content.addSubview(header)

        let copyBtn = makeButton("Copy", action: #selector(copyToPasteboard))
        copyBtn.frame = NSRect(x: 8, y: 5, width: 74, height: 24)
        copyBtn.autoresizingMask = [.maxXMargin]
        header.addSubview(copyBtn)

        let shredBtn = makeButton("Singularity", action: #selector(singularity))
        shredBtn.frame = NSRect(x: frame.width - 118, y: 5, width: 110, height: 24)
        shredBtn.autoresizingMask = [.minXMargin]
        header.addSubview(shredBtn)

        // Status line at the bottom.
        statusLabel = NSTextField(labelWithString: "")
        statusLabel.frame = NSRect(x: 10, y: 4, width: frame.width - 20, height: 16)
        statusLabel.autoresizingMask = [.width, .maxYMargin]
        statusLabel.font = NSFont.systemFont(ofSize: 10)
        statusLabel.textColor = NSColor(calibratedWhite: 0.6, alpha: 1.0)
        content.addSubview(statusLabel)

        // Scrollable text view between header and status line.
        let scroll = NSScrollView(frame: NSRect(x: 8, y: 24, width: frame.width - 16, height: frame.height - 34 - 24))
        scroll.autoresizingMask = [.width, .height]
        scroll.hasVerticalScroller = true
        scroll.borderType = .noBorder
        scroll.drawsBackground = false

        textView = NSTextView(frame: scroll.bounds)
        textView.minSize = NSSize(width: 0, height: 0)
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainerInset = NSSize(width: 6, height: 8)
        textView.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        textView.textColor = NSColor(calibratedWhite: 0.95, alpha: 1.0)
        textView.backgroundColor = NSColor(calibratedWhite: 0.12, alpha: 1.0)
        textView.insertionPointColor = NSColor.systemTeal
        textView.isRichText = false
        textView.allowsUndo = true
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.delegate = self
        textView.textContainer?.widthTracksTextView = true

        scroll.documentView = textView
        content.addSubview(scroll)
    }

    private func makeButton(_ title: String, action: Selector) -> NSButton {
        let b = NSButton(title: title, target: self, action: action)
        b.bezelStyle = .rounded
        b.controlSize = .small
        b.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        return b
    }

    // MARK: Menus

    private func buildMenu() {
        let mainMenu = NSMenu()

        // App menu (Quit).
        let appItem = NSMenuItem()
        mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit Wormhole", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu

        // Edit menu — required for Cmd-X/C/V/A to route without a nib.
        let editItem = NSMenuItem()
        mainMenu.addItem(editItem)
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu

        NSApp.mainMenu = mainMenu
    }

    private func buildStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "🌀"
        let menu = NSMenu()
        menu.addItem(withTitle: "Show Wormhole", action: #selector(showWindow), keyEquivalent: "")
        menu.addItem(withTitle: "Set Server URL…", action: #selector(setServerURL), keyEquivalent: "")
        menu.addItem(withTitle: "Unlock (sealed session)…", action: #selector(unlockAction), keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        let login = NSMenuItem(title: "Launch at Login", action: #selector(toggleLaunchAtLogin(_:)), keyEquivalent: "")
        menu.addItem(login)
        loginItem = login
        menu.addItem(NSMenuItem.separator())
        let quit = NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)
        menu.items.forEach { $0.target = self }
        quit.target = nil // terminate targets the app, not the controller
        statusItem.menu = menu
        updateLoginItemState()
    }

    // MARK: Launch at login (SMAppService, macOS 13+)

    @objc private func toggleLaunchAtLogin(_ sender: NSMenuItem) {
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            setStatus("Launch-at-login failed: \(error.localizedDescription)")
        }
        updateLoginItemState()
    }

    private func updateLoginItemState() {
        let status = SMAppService.mainApp.status
        loginItem?.state = (status == .enabled) ? .on : .off
        if status == .requiresApproval {
            setStatus("Approve “Wormhole” in System Settings ▸ General ▸ Login Items")
        }
    }

    // MARK: Actions

    @objc private func showWindow() {
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    @objc private func copyToPasteboard() {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(textView.string, forType: .string)
        flashStatus("Copied to clipboard")
    }

    @objc private func singularity() {
        guard let url = api("/api/clipboard") else { return }
        Net.shared.request(url, method: "DELETE", token: token) { [weak self] resp in
            guard let self = self else { return }
            if let r = resp, r.status == 200 || r.status == 204 {
                self.setText("", remote: true)
                self.lastServerText = ""
                self.cache("")
                self.flashStatus("Sent to the singularity")
            } else {
                self.flashStatus("Shred failed (\(resp?.status ?? -1))")
            }
        }
    }

    @objc private func setServerURL() {
        guard let entered = prompt(title: "Server URL",
                                   message: "e.g. https://file.internal  or  http://192.168.1.10:9000",
                                   initial: serverURL, secure: false), !entered.isEmpty else { return }
        var v = entered.trimmingCharacters(in: .whitespaces)
        if v.hasSuffix("/") { v.removeLast() }
        UserDefaults.standard.set(v, forKey: kServerURL)
        token = nil; key = nil; promptedThisLock = false
        refresh()
    }

    @objc private func unlockAction() { promptedThisLock = false; beginUnlock() }

    // MARK: Sync

    private func api(_ path: String) -> URL? {
        guard !serverURL.isEmpty else { return nil }
        return URL(string: serverURL + path)
    }

    /// Poll tick: pull current clipboard; adapt to sealed/unsealed and lock changes.
    private func refresh() {
        guard let url = api("/api/clipboard") else { return }
        Net.shared.request(url, token: token) { [weak self] resp in
            guard let self = self else { return }
            guard let r = resp else { self.setStatus("Offline — can't reach \(self.serverURL)"); return }

            if r.status == 401 {
                // Session is locked and we have no (valid) token → need the password.
                self.sealed = true; self.token = nil; self.key = nil
                self.setStatus("🔒 Sealed — choose Unlock from the 🌀 menu")
                if !self.promptedThisLock { self.promptedThisLock = true; self.beginUnlock() }
                return
            }
            guard r.status == 200, let j = r.json else {
                self.setStatus("Server error (\(r.status))"); return
            }

            if let enc = j["encrypted_b64"] as? String {
                // Sealed clipboard.
                self.sealed = true
                guard let key = self.key, let blob = Data(base64Encoded: enc),
                      let pt = Crypto.decrypt(key: key, blob: blob), let s = String(data: pt, encoding: .utf8) else {
                    self.setStatus("🔒 Sealed — Unlock to read"); return
                }
                self.applyServerText(s); self.setStatus("🔒 Sealed · synced")
            } else if let t = j["text"] as? String {
                // Plaintext clipboard.
                self.sealed = false; self.key = nil; self.promptedThisLock = false
                self.applyServerText(t); self.setStatus("Unsealed · synced")
            } else {
                // No content field means empty clipboard.
                let empty = ""
                self.sealed = (self.key != nil)
                self.applyServerText(empty)
                self.setStatus(self.sealed ? "🔒 Sealed · synced" : "Unsealed · synced")
            }
        }
    }

    /// Update the box from the server unless the user is mid-edit.
    private func applyServerText(_ serverText: String) {
        lastServerText = serverText
        cache(serverText)
        if Date() < suppressRemoteUntil { return }          // user typing recently
        if serverText == textView.string { return }          // no change
        setText(serverText, remote: true)
    }

    private func setText(_ s: String, remote: Bool) {
        applyingRemote = remote
        let sel = textView.selectedRange()
        textView.string = s
        // Keep the caret sane after a programmatic replace.
        let loc = min(sel.location, (s as NSString).length)
        textView.setSelectedRange(NSRange(location: loc, length: 0))
        applyingRemote = false
    }

    // Debounced save on edit.
    func textDidChange(_ notification: Notification) {
        guard !applyingRemote else { return }
        suppressRemoteUntil = Date().addingTimeInterval(2.0)
        saveWork?.cancel()
        let text = textView.string
        let work = DispatchWorkItem { [weak self] in self?.saveText(text) }
        saveWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6, execute: work)
    }

    private func saveText(_ text: String) {
        guard let url = api("/api/clipboard") else { return }
        if text == lastServerText { return }

        // Clearing the box shreds the server clipboard. An empty POST is rejected
        // (400 "No content provided"), which would otherwise leave the old text on
        // the server and let the next poll pop it back into the box.
        if text.isEmpty {
            Net.shared.request(url, method: "DELETE", token: token) { [weak self] resp in
                guard let self = self else { return }
                if let r = resp, r.status == 200 || r.status == 204 {
                    self.lastServerText = ""; self.cache("")
                    self.setStatus(self.sealed ? "🔒 Sealed · cleared" : "Unsealed · cleared")
                } else if resp?.status == 401 {
                    self.token = nil; self.key = nil; self.promptedThisLock = false
                    self.setStatus("🔒 Sealed — Unlock to sync"); self.beginUnlock()
                } else {
                    self.setStatus("Clear failed (\(resp?.status ?? -1))")
                }
            }
            return
        }

        var body: [String: Any]
        if sealed {
            guard let key = key, let ct = Crypto.encrypt(key: key, plaintext: Data(text.utf8)) else {
                flashStatus("🔒 Unlock before typing"); return
            }
            body = ["encrypted_b64": ct.base64EncodedString()]
        } else {
            body = ["text": text]
        }
        Net.shared.request(url, method: "POST", token: token, body: body) { [weak self] resp in
            guard let self = self else { return }
            if let r = resp, r.status == 201 || r.status == 200 {
                self.lastServerText = text; self.cache(text)
                self.setStatus(self.sealed ? "🔒 Sealed · saved" : "Unsealed · saved")
            } else if resp?.status == 401 {
                self.token = nil; self.key = nil; self.promptedThisLock = false
                self.setStatus("🔒 Sealed — Unlock to save"); self.beginUnlock()
            } else {
                self.setStatus("Save failed (\(resp?.status ?? -1)) — kept locally")
            }
        }
    }

    // MARK: Unlock flow (sealed sessions)

    private func beginUnlock() {
        guard !serverURL.isEmpty else { setStatus("Set a server URL first"); return }
        guard let password = prompt(title: "Unlock sealed session",
                                    message: "Enter the session password (E2EE, stays on this Mac).",
                                    initial: "", secure: true), !password.isEmpty else { return }
        setStatus("Deriving key…")
        guard let saltURL = api("/api/lock/salt") else { return }
        Net.shared.request(saltURL) { [weak self] resp in
            guard let self = self else { return }
            guard let r = resp, r.status == 200, let saltB64 = r.json?["salt_b64"] as? String,
                  let salt = Data(base64Encoded: saltB64) else {
                self.setStatus("Couldn't fetch salt (session not sealed?)"); return
            }
            // PBKDF2 is ~1s; do it off the main thread.
            DispatchQueue.global(qos: .userInitiated).async {
                guard let key = Crypto.deriveKey(password: password, salt: salt) else {
                    DispatchQueue.main.async { self.setStatus("Key derivation failed") }; return
                }
                let hash = Crypto.keyHash(key).base64EncodedString()
                DispatchQueue.main.async {
                    guard let unlockURL = self.api("/api/unlock") else { return }
                    Net.shared.request(unlockURL, method: "POST", body: ["keyHash_b64": hash]) { resp in
                        guard let r = resp else { self.setStatus("Offline"); return }
                        if r.status == 401 { self.setStatus("Wrong password"); self.promptedThisLock = false; return }
                        guard r.status == 200, let tok = r.json?["token"] as? String else {
                            self.setStatus("Unlock failed (\(r.status))"); return
                        }
                        self.token = tok; self.key = key; self.sealed = true
                        // Populate from the returned encrypted clipboard blob.
                        if let enc = r.json?["encryptedClipboard_b64"] as? String,
                           let blob = Data(base64Encoded: enc),
                           let pt = Crypto.decrypt(key: key, blob: blob),
                           let s = String(data: pt, encoding: .utf8) {
                            self.applyServerText(s)
                        }
                        self.setStatus("🔓 Unlocked · synced")
                    }
                }
            }
        }
    }

    // MARK: Small helpers

    private func cache(_ s: String) { UserDefaults.standard.set(s, forKey: kCachedText) }
    private func setStatus(_ s: String) { statusLabel?.stringValue = s }
    private func flashStatus(_ s: String) {
        setStatus(s)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { [weak self] in
            guard let self = self else { return }
            if self.statusLabel?.stringValue == s { self.setStatus(self.sealed ? "🔒 Sealed" : "Connected") }
        }
    }

    /// Modal text prompt. Returns nil if cancelled.
    private func prompt(title: String, message: String, initial: String, secure: Bool) -> String? {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        let field: NSTextField = secure ? NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
                                        : NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        field.stringValue = initial
        alert.accessoryView = field
        alert.window.initialFirstResponder = field
        return alert.runModal() == .alertFirstButtonReturn ? field.stringValue : nil
    }
}

// MARK: - Bootstrap (top-level, no @main)

let app = NSApplication.shared
let controller = AppController()
app.delegate = controller
app.setActivationPolicy(.accessory)
app.run()
