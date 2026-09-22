import Foundation
import CoreBluetooth
import CryptoKit

/// BLE client that talks to ap-ble-agent (protocol v2) on the Pi.
///
/// Framing: the first byte of every write/notification is a header — bit7 = FIN, bits0-6 = sequence.
/// Handshake (plaintext): hello{nonce_c} → challenge{nonce_s, proof_s} → auth{proof_c} → ok.
/// Afterwards: every message is counter(8B BE) || ChaCha20-Poly1305(K, nonce = dir(4B)||counter, JSON).
/// K = HKDF-SHA256(token, salt = nonce_c||nonce_s, info "piap-ble-v2"). A listening subscriber sees ciphertext only.
final class BLEClient: NSObject, ObservableObject {
    static let serviceUUID = CBUUID(string: "7f2a0001-9c1e-4b7a-8d3e-5a6b7c8d9e0f")
    static let rxUUID      = CBUUID(string: "7f2a0002-9c1e-4b7a-8d3e-5a6b7c8d9e0f")
    static let txUUID      = CBUUID(string: "7f2a0003-9c1e-4b7a-8d3e-5a6b7c8d9e0f")
    static let protoVersion = 2

    enum State: Equatable {
        case starting, off, idle, scanning, connecting, discovering, pairing, authenticating, ready, error(String)
        var label: String {
            switch self {
            case .starting: return "Preparing Bluetooth…"
            case .off: return "Bluetooth is off"
            case .idle: return "Not connected"
            case .scanning: return "Scanning…"
            case .connecting: return "Connecting…"
            case .discovering: return "Discovering services…"
            case .pairing: return "Pairing…"
            case .authenticating: return "Authenticating…"
            case .ready: return "Connected (encrypted)"
            case .error(let e): return "Error: \(e)"
            }
        }
    }

    struct Found: Identifiable, Equatable {
        let id: UUID; let name: String; var rssi: Int
        static func == (a: Found, b: Found) -> Bool { a.id == b.id }
    }

    @Published private(set) var state: State = .starting
    @Published private(set) var found: [Found] = []
    @Published private(set) var peripheralName: String = ""
    @Published private(set) var connectedID: UUID? = nil
    @Published private(set) var mtu: Int = 20
    @Published var log: [String] = []

    var token: String = ""
    var onDisconnect: (() -> Void)?

    private var central: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var rx: CBCharacteristic?
    private var tx: CBCharacteristic?
    private var rxSeq: UInt8 = 0
    private var inBuf = Data()
    private var inSeq: UInt8 = 0
    private var nextID = 1
    private var pending: [Int: CheckedContinuation<[String: Any], Error>] = [:]
    private var pendingTimers: [Int: DispatchWorkItem] = [:]
    private var writeQueue: [Data] = []
    private var writing = false
    private var handshakeCont: CheckedContinuation<[String: Any], Error>?
    private var handshakeTimer: DispatchWorkItem?
    // session key and counters
    private var sessionKey: SymmetricKey?
    private var c2pNext: UInt64 = 0
    private var p2cLast: Int64 = -1
    private let logFile: FileHandle?

    override init() {
        let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("PiAPManager.log")
        if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) }
        logFile = try? FileHandle(forWritingTo: url); logFile?.seekToEndOfFile()
        super.init()
        central = CBCentralManager(delegate: self, queue: .main)
        note("started (proto v\(Self.protoVersion))")
    }

    func note(_ s: String) {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss.SSS"
        let line = "\(f.string(from: Date())) \(s)"
        DispatchQueue.main.async { self.log.append(line); if self.log.count > 400 { self.log.removeFirst(self.log.count - 400) } }
        logFile?.write((line + "\n").data(using: .utf8)!)
    }

    // MARK: - scanning / connecting
    func startScan() {
        guard central.state == .poweredOn else { if state != .starting { state = .off }; return }
        found = []; state = .scanning
        central.scanForPeripherals(withServices: [Self.serviceUUID], options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        note("scan started")
    }

    func stopScan() { central.stopScan(); if state == .scanning { state = .idle } }

    func connect(_ id: UUID) {
        guard let p = central.retrievePeripherals(withIdentifiers: [id]).first else { state = .error("device not found"); return }
        central.stopScan()
        peripheral = p; p.delegate = self; peripheralName = p.name ?? "PiAP"; connectedID = id
        state = .connecting; central.connect(p, options: nil)
        note("connecting: \(peripheralName) \(id)")
    }

    func disconnect() {
        if let p = peripheral { central.cancelPeripheralConnection(p) }
        cleanup(reason: "user")
    }

    private func cleanup(reason: String) {
        for (_, c) in pending { c.resume(throwing: BLEError.disconnected) }
        pending.removeAll(); pendingTimers.values.forEach { $0.cancel() }; pendingTimers.removeAll()
        handshakeTimer?.cancel(); handshakeTimer = nil
        handshakeCont?.resume(throwing: BLEError.disconnected); handshakeCont = nil
        writeQueue.removeAll(); writing = false; inBuf = Data(); inSeq = 0; rxSeq = 0
        sessionKey = nil; c2pNext = 0; p2cLast = -1
        rx = nil; tx = nil; peripheral = nil; connectedID = nil
        if state != .idle { note("connection closed (\(reason))") }
        state = .idle
        onDisconnect?()
    }

    // MARK: - RPC
    enum BLEError: LocalizedError {
        case notReady, disconnected, timeout, remote(String), auth(String), badResponse, crypto
        var errorDescription: String? {
            switch self {
            case .notReady: return "not connected"
            case .disconnected: return "connection lost"
            case .timeout: return "timed out"
            case .remote(let m): return m
            case .auth(let m): return "authentication: \(m)"
            case .badResponse: return "invalid response"
            case .crypto: return "encryption error"
            }
        }
    }

    @discardableResult
    func call(_ op: String, args: [String: Any] = [:], timeout: TimeInterval = 20) async throws -> Any {
        guard state == .ready, sessionKey != nil else { throw BLEError.notReady }
        let id = nextID; nextID += 1
        var msg: [String: Any] = ["id": id, "op": op]
        if !args.isEmpty { msg["args"] = args }
        let resp: [String: Any] = try await withCheckedThrowingContinuation { cont in
            pending[id] = cont
            let w = DispatchWorkItem { [weak self] in
                guard let self, let c = self.pending.removeValue(forKey: id) else { return }
                self.note("id=\(id) \(op): timed out"); c.resume(throwing: BLEError.timeout)
                // The Pi acks every long operation, so a timeout means the link is dead — usually because the
                // agent restarted and our cached GATT handles went stale. Drop it instead of spinning forever;
                // the connect screen comes back and a fresh connection rebuilds the handles.
                self.disconnect()
                self.state = .error("no answer from the Pi — disconnected, connect again")
            }
            pendingTimers[id] = w
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: w)
            do { try sendSealed(msg) } catch { pending.removeValue(forKey: id); w.cancel(); cont.resume(throwing: error) }
        }
        if let ok = resp["ok"] as? Bool, ok { return resp["result"] ?? [:] }
        let err = (resp["error"] as? String) ?? "unknown error"
        if err.contains("session invalid") || err.contains("unauthorized") { // the Pi dropped the session → handshake again
            note("session dropped, re-authenticating"); Task { await authenticate() }
        }
        throw BLEError.remote(err)
    }

    func callDict(_ op: String, args: [String: Any] = [:], timeout: TimeInterval = 20) async throws -> [String: Any] {
        (try await call(op, args: args, timeout: timeout) as? [String: Any]) ?? [:]
    }
    func callList(_ op: String, args: [String: Any] = [:], timeout: TimeInterval = 20) async throws -> [[String: Any]] {
        (try await call(op, args: args, timeout: timeout) as? [[String: Any]]) ?? []
    }

    // MARK: - handshake (v2)
    private func hmacHex(_ msg: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(msg.utf8), using: SymmetricKey(data: Data(token.utf8)))
        return mac.map { String(format: "%02x", $0) }.joined()
    }

    private func handshakeStep(_ obj: [String: Any]) async throws -> [String: Any] {
        try await withCheckedThrowingContinuation { c in
            handshakeCont = c
            let w = DispatchWorkItem { [weak self] in
                if let cc = self?.handshakeCont { self?.handshakeCont = nil; cc.resume(throwing: BLEError.timeout) }
            }
            handshakeTimer?.cancel(); handshakeTimer = w
            DispatchQueue.main.asyncAfter(deadline: .now() + 15, execute: w)
            sendPlain(obj)
        }
    }

    @MainActor
    private func authenticate() async {
        state = .authenticating; sessionKey = nil
        var ncBytes = [UInt8](repeating: 0, count: 16); _ = SecRandomCopyBytes(kSecRandomDefault, 16, &ncBytes)
        let nc = ncBytes.map { String(format: "%02x", $0) }.joined()
        do {
            let ch = try await handshakeStep(["op": "hello", "v": Self.protoVersion, "nonce": nc, "id": 0])
            guard ch["op"] as? String == "challenge", let ns = ch["nonce"] as? String, let proofS = ch["proof"] as? String else {
                let e = (ch["error"] as? String) ?? "unexpected response"; state = .error(e); note("hello: \(e)"); return
            }
            // Verify that the Pi knows the token (a fake "PiAP" peripheral is rejected here)
            guard proofS == hmacHex("srv|\(nc)|\(ns)") else { state = .error("device identity could not be verified (fake PiAP?)"); note("SERVER PROOF WRONG"); disconnect(); return }
            note("← challenge OK (server proof valid, \(ch["name"] ?? "?"))")
            let ok = try await handshakeStep(["op": "auth", "proof": hmacHex("cli|\(nc)|\(ns)"), "id": 0])
            guard ok["ok"] as? Bool == true else {
                let e = (ok["error"] as? String) ?? "reddedildi"; note("← auth RED: \(e)")
                state = .error(e.contains("authentication") ? "token rejected" : e); disconnect(); return
            }
            // session key
            let salt = Data(hex: nc)! + Data(hex: ns)!
            sessionKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: Data(token.utf8)), salt: salt, info: Data("piap-ble-v2".utf8), outputByteCount: 32)
            c2pNext = 0; p2cLast = -1
            state = .ready; note("ready — encrypted session (MTU \(mtu))")
        } catch {
            note("handshake error: \(error)")
            // Release the link. A half-open link (for example after the Pi's agent restarted and our cached GATT
            // handles went stale) would otherwise stay open and block every later attempt from this Mac.
            disconnect()
            state = .error("handshake failed: \(error.localizedDescription) — disconnected, try again")
        }
    }

    // MARK: - encryption
    private static let dirC2P = Data([0x63, 0x32, 0x70, 0x00]), dirP2C = Data([0x70, 0x32, 0x63, 0x00])

    private func seal(_ obj: [String: Any]) throws -> Data {
        guard let key = sessionKey else { throw BLEError.notReady }
        let pt = try JSONSerialization.data(withJSONObject: obj)
        var ctrBE = c2pNext.bigEndian; let ctrData = Data(bytes: &ctrBE, count: 8); c2pNext += 1
        let nonce = try ChaChaPoly.Nonce(data: Self.dirC2P + ctrData)
        let box = try ChaChaPoly.seal(pt, using: key, nonce: nonce)
        return ctrData + box.ciphertext + box.tag
    }

    private func open(_ blob: Data) throws -> [String: Any] {
        guard let key = sessionKey, blob.count >= 8 + 16 else { throw BLEError.crypto }
        let ctrData = blob.prefix(8)
        let ctr = ctrData.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        guard Int64(ctr) > p2cLast else { throw BLEError.crypto }
        let nonce = try ChaChaPoly.Nonce(data: Self.dirP2C + ctrData)
        let body = blob.dropFirst(8)
        let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: body.dropLast(16), tag: body.suffix(16))
        let pt = try ChaChaPoly.open(box, using: key)
        p2cLast = Int64(ctr)
        guard let obj = try JSONSerialization.jsonObject(with: pt) as? [String: Any] else { throw BLEError.badResponse }
        return obj
    }

    // MARK: - framing
    private func sendPlain(_ obj: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return }
        note("→ \(obj["op"] ?? "?") (plain, \(data.count)B)"); enqueue(data)
    }
    private func sendSealed(_ obj: [String: Any]) throws {
        let data = try seal(obj)
        note("→ \(obj["op"] ?? "?") (encrypted, \(data.count)B)"); enqueue(data)
    }
    private func enqueue(_ data: Data) {
        guard let p = peripheral, let rx else { note("send: no rx characteristic"); return }
        let chunk = max(16, min(mtu, 512) - 1)
        var i = 0
        repeat {
            let end = min(i + chunk, data.count)
            let fin: UInt8 = end == data.count ? 0x80 : 0
            var d = Data([fin | (rxSeq & 0x7f)]); rxSeq = (rxSeq &+ 1) & 0x7f
            d.append(data[i..<end]); writeQueue.append(d); i = end
        } while i < data.count
        pumpWrites(p, rx)
    }
    private func pumpWrites(_ p: CBPeripheral, _ rx: CBCharacteristic) {
        guard !writing, !writeQueue.isEmpty else { return }
        writing = true; p.writeValue(writeQueue.removeFirst(), for: rx, type: .withResponse)
    }

    private func received(_ raw: Data) {
        guard let hdr = raw.first else { return }
        let fin = hdr & 0x80 != 0, seq = hdr & 0x7f
        if seq != inSeq { inBuf = Data(); inSeq = seq }
        inBuf.append(raw.dropFirst()); inSeq = (seq &+ 1) & 0x7f
        guard fin else { return }
        let data = inBuf; inBuf = Data()
        if sessionKey != nil, state == .ready {
            if let obj = try? open(data) { route(obj) } else {
                // it may be a plaintext error ("session invalid") — try that
                if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { note("← plain (outside the session): \(obj["error"] ?? obj)"); route(obj) }
                else { note("← undecryptable frame (\(data.count)B) — ignored") }
            }
            return
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { note("← invalid JSON"); return }
        if let c = handshakeCont { handshakeCont = nil; handshakeTimer?.cancel(); c.resume(returning: obj); return }
        route(obj)
    }

    private func route(_ obj: [String: Any]) {
        guard let id = obj["id"] as? Int else { note("← id'siz: \(obj)"); return }
        if obj["ack"] as? Bool == true { note("← ack id=\(id) (\(obj["op"] ?? "")) working…"); return }
        guard let cont = pending.removeValue(forKey: id) else { note("← bilinmeyen id=\(id)"); return }
        pendingTimers.removeValue(forKey: id)?.cancel()
        note("← id=\(id) \(obj["ok"] as? Bool == true ? "ok" : "ERROR: \(obj["error"] ?? "")")")
        cont.resume(returning: obj)
    }
}

extension Data {
    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var d = Data(capacity: hex.count / 2); var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else { return nil }
            d.append(b); idx = next
        }
        self = d
    }
}

// MARK: - CBCentralManagerDelegate
extension BLEClient: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        note("BT state: \(c.state.rawValue)")
        switch c.state {
        case .poweredOn: if state == .off || state == .starting { state = .idle }
        case .unauthorized: state = .error("Bluetooth permission denied (System Settings → Privacy → Bluetooth)")
        case .unknown, .resetting: state = .starting
        default: state = .off
        }
    }
    func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral, advertisementData: [String: Any], rssi: NSNumber) {
        let name = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? p.name ?? "PiAP"
        if let i = found.firstIndex(where: { $0.id == p.identifier }) { found[i].rssi = rssi.intValue }
        else { found.append(Found(id: p.identifier, name: name, rssi: rssi.intValue)); note("found: \(name) rssi=\(rssi)") }
    }
    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        state = .discovering; note("connected, discovering services"); p.discoverServices([Self.serviceUUID])
    }
    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        state = .error("could not connect: \(error?.localizedDescription ?? "?")"); cleanup(reason: "fail")
    }
    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        cleanup(reason: error?.localizedDescription ?? "uzak taraf")
    }
}

// MARK: - CBPeripheralDelegate
extension BLEClient: CBPeripheralDelegate {
    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let s = p.services?.first(where: { $0.uuid == Self.serviceUUID }) else { state = .error("no PiAP service: \(error?.localizedDescription ?? "")"); return }
        p.discoverCharacteristics([Self.rxUUID, Self.txUUID], for: s)
    }
    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        rx = s.characteristics?.first { $0.uuid == Self.rxUUID }; tx = s.characteristics?.first { $0.uuid == Self.txUUID }
        guard let tx, rx != nil else { state = .error("characteristics missing"); return }
        mtu = p.maximumWriteValueLength(for: .withResponse); note("characteristics OK, MTU(write)=\(mtu)")
        state = .pairing; p.setNotifyValue(true, for: tx)
    }
    func peripheral(_ p: CBPeripheral, didUpdateNotificationStateFor ch: CBCharacteristic, error: Error?) {
        if let error {
            let ns = error as NSError
            if ns.domain == CBATTErrorDomain, ns.code == CBATTError.insufficientEncryption.rawValue || ns.code == CBATTError.insufficientAuthentication.rawValue {
                state = .error("pairing refused: the pairing window on the Pi is closed. Run `sudo ap-ctl ble pair 120` on the Pi and try again.")
            } else { state = .error("notify: \(error.localizedDescription)") }
            note("notify error: \(error)"); return
        }
        guard ch.isNotifying else { return }
        note("TX notifications on"); Task { await authenticate() }
    }
    func peripheral(_ p: CBPeripheral, didWriteValueFor ch: CBCharacteristic, error: Error?) {
        writing = false
        if let error {
            note("write error: \(error.localizedDescription) — queue cleared")
            writeQueue.removeAll()
            let ns = error as NSError
            if ns.domain == CBATTErrorDomain, ns.code == CBATTError.insufficientEncryption.rawValue || ns.code == CBATTError.insufficientAuthentication.rawValue {
                state = .error("encrypted write refused: not paired. Run `sudo ap-ctl ble pair 120` on the Pi and try again.")
            }
            if let c = handshakeCont { handshakeCont = nil; handshakeTimer?.cancel(); c.resume(throwing: BLEError.remote(error.localizedDescription)) }
            return
        }
        if let rx { pumpWrites(p, rx) }
    }
    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        if let error { note("read/notify error: \(error.localizedDescription)"); return }
        guard ch.uuid == Self.txUUID, let v = ch.value else { return }
        received(v)
    }
}
