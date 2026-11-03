// Mac Health.app: a private window around the local server.
//
// macOS ties Full Disk Access to this exact signed app, so granting it doesn't extend to Terminal.
// Before starting, the app checks its Python and HTML files against hashes built into its binary, then
// hands those exact bytes to Python through a pipe, so no code is read from disk after the check.
// The token travels the same way and is never written to disk.
import Cocoa
import CryptoKit
import Security
import WebKit

// Runs only code the app has already verified. Fixed text inside this signed binary.
private let bootstrap = """
import json, sys, types
payload = json.loads(sys.stdin.buffer.read(int(sys.stdin.buffer.readline())))
module = types.ModuleType("scanners")
exec(compile(payload["files"]["scanners.py"], "scanners.py", "exec"), module.__dict__)
sys.modules["scanners"] = module
exec(compile(payload["files"]["server.py"], "server.py", "exec"), {"__name__": "__main__", "MAC_HEALTH_PAYLOAD": payload})
"""

private let pythonPath = "/Library/Developer/CommandLineTools/usr/bin/python3"
private let scanRequest = Notification.Name("local.machealth.scan-request")

// Encrypts saved results. The item trusts only this app, so macOS asks you before any other program reads it.
// An item that's open to every program, isn't in the expected format or wasn't made for this app is replaced,
// because another program could have planted it to know the key. Only the login keychain is used, because
// any program can put another keychain ahead of it in the search list without a prompt.
// This is not complete protection: a program running as you can delete the item and plant one that trusts
// only this app, without a prompt and at any time, and that can't be told apart. Closing that needs the
// data-protection keychain, which needs an Apple team ID this locally signed app doesn't have.
private let dataKeyQuery: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                           kSecAttrService as String: "local.machealth.data-key",
                                           kSecAttrAccount as String: "saved-results"]

private func trustedData(_ app: SecTrustedApplication) -> Data? {
    var data: CFData?
    return SecTrustedApplicationCopyData(app, &data) == errSecSuccess ? data as Data? : nil
}

private func thisApp() -> SecTrustedApplication? {
    var app: SecTrustedApplication?
    return SecTrustedApplicationCreateFromPath(nil, &app) == errSecSuccess ? app : nil
}

private func onlyThisAppMayRead(_ item: SecKeychainItem) -> Bool {
    var access: SecAccess?
    guard SecKeychainItemCopyAccess(item, &access) == errSecSuccess, let access = access,
          let me = thisApp(), let mine = trustedData(me),
          let lists = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt) as? [SecACL], !lists.isEmpty else { return false }
    for list in lists {
        var apps: CFArray?
        var description: CFString?
        var prompt = SecKeychainPromptSelector()
        // No list at all means every program may read it.
        guard SecACLCopyContents(list, &apps, &description, &prompt) == errSecSuccess,
              let trusted = apps as? [SecTrustedApplication],
              trusted.allSatisfy({ trustedData($0) == mine }) else { return false }
    }
    return true
}

// Remembered outside ~/.mac-health, so replacing the key is noticed even if the saved results were deleted first.
// A program running as you could delete this too, so it narrows the gap rather than closing it.
private let hadKeyMarker = "local.machealth.had-data-key"

private func savedDataKey() -> (key: String, replaced: Bool)? {
    guard let key = currentDataKey() else { return nil }
    let replaced = key.created && UserDefaults.standard.bool(forKey: hadKeyMarker)
    UserDefaults.standard.set(true, forKey: hadKeyMarker)
    return (key.value, replaced)
}

private func currentDataKey() -> (value: String, created: Bool)? {
    var keychain: SecKeychain?
    let path = NSHomeDirectory() + "/Library/Keychains/login.keychain-db"
    guard SecKeychainOpen(path, &keychain) == errSecSuccess, let keychain = keychain else { return nil }
    var inLogin = dataKeyQuery
    inLogin[kSecMatchSearchList as String] = [keychain]
    var query = inLogin
    query[kSecReturnData as String] = true
    query[kSecReturnRef as String] = true
    var found: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &found)
    if status == errSecSuccess, let result = found as? [String: Any], let data = result[kSecValueData as String] as? Data {
        let key = String(decoding: data, as: UTF8.self)
        let wellFormed = key.count == 64 && key.allSatisfy { "0123456789abcdef".contains($0) }
        if wellFormed, let ref = result[kSecValueRef as String], onlyThisAppMayRead(ref as! SecKeychainItem) { return (key, false) }
        guard SecItemDelete(inLogin as CFDictionary) == errSecSuccess else { return nil }
    } else if status != errSecItemNotFound {
        return nil
    }
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess, let me = thisApp() else { return nil }
    var access: SecAccess?
    guard SecAccessCreate("Mac Health saved results" as CFString, [me] as CFArray, &access) == errSecSuccess, let access = access else { return nil }
    let key = bytes.map { String(format: "%02x", $0) }.joined()
    var item = dataKeyQuery
    item[kSecAttrLabel as String] = "Mac Health saved results"
    item[kSecValueData as String] = Data(key.utf8)
    item[kSecAttrAccess as String] = access
    item[kSecUseKeychain as String] = keychain
    return SecItemAdd(item as CFDictionary, nil) == errSecSuccess ? (key, true) : nil
}

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, NSWindowDelegate {
    private var window: NSWindow!
    private var server: Process?
    private var stdinPipe: Pipe?
    private var origin = ""
    private var webView: WKWebView?
    private var scanWhenLoaded = CommandLine.arguments.contains("--scan")
    private var loaded = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        // A scan only reads, so a request can start one but carries nothing else.
        DistributedNotificationCenter.default().addObserver(forName: scanRequest, object: nil, queue: .main) { [weak self] _ in
            NSApp.activate(ignoringOtherApps: true)
            self?.startScan()
        }
        signal(SIGPIPE, SIG_IGN)  // a server that dies early should show an alert, not kill the app silently
        guard let resources = Bundle.main.resourceURL, let files = verifiedFiles(in: resources) else {
            fail("Mac Health's files have changed since it was built, so it won't run. Rebuild it with build.sh.")
            return
        }
        startServer(files: files)
    }

    private func verifiedFiles(in folder: URL) -> [String: String]? {
        var files: [String: String] = [:]
        for (name, expected) in expectedHashes {
            guard let data = try? Data(contentsOf: folder.appendingPathComponent(name)) else { return nil }
            let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            if digest != expected { return nil }
            files[name] = String(decoding: data, as: UTF8.self)
        }
        return files
    }

    private func randomToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("Couldn't create a secure token.")
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func startServer(files: [String: String]) {
        let token = randomToken()
        let process = Process()
        let input = Pipe()
        let output = Pipe()
        // The real interpreter, not the /usr/bin/python3 shim, which finds it through a cache your account can change.
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: pythonPath),
              (attributes[.ownerAccountID] as? NSNumber)?.intValue == 0 else {
            fail("Mac Health needs the Command Line Tools. Install them with: xcode-select --install")
            return
        }
        process.executableURL = URL(fileURLWithPath: pythonPath)
        // -I and -B ignore Python environment settings and local modules, and never write cache files.
        process.arguments = ["-I", "-B", "-c", bootstrap]
        process.environment = [
            "HOME": NSHomeDirectory(),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "en_US.UTF-8",
            "MAC_HEALTH_APP": Bundle.main.bundlePath,
        ]
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                if self?.window == nil {
                    self?.fail("Mac Health's local service stopped while starting.")
                } else {
                    NSApp.terminate(nil)
                }
            }
        }
        do {
            try process.run()
        } catch {
            fail("Mac Health couldn't start its local service.")
            return
        }
        server = process
        stdinPipe = input
        var payload: [String: Any] = ["token": token, "files": files]
        if let key = savedDataKey() {
            payload["data_key"] = key.key
            payload["key_replaced"] = key.replaced
        }
        guard let body = try? JSONSerialization.data(withJSONObject: payload) else {
            fail("Mac Health couldn't start its local service.")
            return
        }
        let message = Data("\(body.count)\n".utf8) + body
        // The code is larger than a pipe holds, so writing waits until Python has read it.
        DispatchQueue.global().async {
            do {
                try input.fileHandleForWriting.write(contentsOf: message)
            } catch {
                DispatchQueue.main.async { self.fail("Mac Health couldn't start its local service.") }
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in
            if self?.window == nil {
                self?.fail("Mac Health's local service didn't start in time.")
            }
        }

        DispatchQueue.global().async {
            let line = self.readLine(from: output.fileHandleForReading)
            DispatchQueue.main.async {
                guard line.hasPrefix("PORT "), let port = Int(line.dropFirst(5)) else {
                    self.fail("Mac Health couldn't start its local service.")
                    return
                }
                self.openWindow(port: port, token: token)
            }
        }
    }

    private func readLine(from handle: FileHandle) -> String {
        var data = Data()
        while true {
            let byte = handle.readData(ofLength: 1)
            if byte.isEmpty || byte.first == 10 { break }
            data.append(byte)
        }
        return String(decoding: data, as: UTF8.self)
    }

    private func openWindow(port: Int, token: String) {
        origin = "http://127.0.0.1:\(port)"
        let configuration = WKWebViewConfiguration()
        // Nothing is kept on disk, so the address and token never reach a browser history or extension.
        configuration.websiteDataStore = .nonPersistent()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        self.webView = webView
        webView.navigationDelegate = self
        webView.uiDelegate = self
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 820),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Mac Health"
        window.minSize = NSSize(width: 480, height: 500)
        window.contentView = webView
        window.delegate = self
        window.center()
        window.setFrameAutosaveName("MacHealthWindow")
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        webView.load(URLRequest(url: URL(string: "\(origin)/#\(token)")!))
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        loaded = true
        if scanWhenLoaded {
            scanWhenLoaded = false
            startScan()
        }
    }

    private func startScan() {
        // A request that arrives while the window is still loading would otherwise be lost.
        guard loaded, let webView = webView else {
            scanWhenLoaded = true
            return
        }
        webView.evaluateJavaScript("view.tab = 'overview'; startScan().catch(() => {}); void 0", completionHandler: nil)
    }

    // Only the local dashboard may load in this window.
    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let url = action.request.url?.absoluteString ?? ""
        decisionHandler(url == origin || url.hasPrefix(origin + "/") ? .allow : .cancel)
    }

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        return nil
    }

    private func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit Mac Health", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        let editItem = NSMenuItem()
        main.addItem(editItem)
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = editMenu
        NSApp.mainMenu = main
    }

    private func fail(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Mac Health can't open"
        alert.informativeText = message
        alert.alertStyle = .critical
        alert.runModal()
        NSApp.terminate(nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        server?.terminationHandler = nil
        // Closing the pipe tells the server to exit, and terminate() covers anything unexpected.
        try? stdinPipe?.fileHandleForWriting.close()
        server?.terminate()
    }
}

// Sent by the machealth command when the app is already open. Exits without opening anything.
if CommandLine.arguments.contains("--request-scan") {
    DistributedNotificationCenter.default().postNotificationName(scanRequest, object: nil, userInfo: nil, deliverImmediately: true)
    RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.2))
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
