// Mac Health.app: a private window around the local server.
//
// macOS ties Full Disk Access to this exact signed app, so granting it doesn't extend to Terminal.
// Before starting, the app checks its Python and HTML files against hashes built into its binary, then
// hands those exact bytes to Python through a pipe, so no code is read from disk after the check.
// The token travels the same way and is never written to disk.
import Cocoa
import CryptoKit
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

private let scanRequest = Notification.Name("local.machealth.scan-request")

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, NSWindowDelegate {
    private var window: NSWindow!
    private var server: Process?
    private var stdinPipe: Pipe?
    private var origin = ""
    private var webView: WKWebView?
    private var scanWhenLoaded = CommandLine.arguments.contains("--scan")

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
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
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
        guard let body = try? JSONSerialization.data(withJSONObject: ["token": token, "files": files]) else {
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
        if scanWhenLoaded {
            scanWhenLoaded = false
            startScan()
        }
    }

    private func startScan() {
        webView?.evaluateJavaScript("view.tab = 'overview'; startScan().catch(() => {}); void 0", completionHandler: nil)
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
