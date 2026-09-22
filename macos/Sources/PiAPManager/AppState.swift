import Foundation
import SwiftUI
import Security
import Combine

// MARK: - Keychain (cihaz başına token)
enum Keychain {
    static let service = "com.mithat.piapmanager"
    static func account(_ id: UUID) -> String { "ble-token-\(id.uuidString)" }
    static func load(device id: UUID) -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account(id), kSecReturnData as String: true]
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    static func save(_ token: String, device id: UUID) {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account(id)]
        SecItemDelete(base as CFDictionary)
        var q = base; q[kSecValueData as String] = Data(token.utf8); q[kSecAttrLabel as String] = "PiAP Manager — \(id.uuidString.prefix(8))"
        SecItemAdd(q as CFDictionary, nil)
    }
    static func delete(device id: UUID) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account(id)]
        SecItemDelete(q as CFDictionary)
    }
}

// MARK: - Modeller
struct APInfo { var iface = "", ssid = "?", up = false, channel = 0, width = 0, band = "" }
struct VPNInfo { var iface = "", profile: String? = nil, up = false, healthy = false, endpoint = "-", handshakeAge: Int? = nil, address = "-", rx = 0, tx = 0, mtu = 0 }
/// Atama sabiti: SSID ↔ profil ↔ sunucu anahtarı ↔ radyo MAC. Pi tarafında ap-pin.sh sapmada yayını durdurur (fail-closed).
struct PinInfo { var pinned = false, profile: String? = nil, ssid: String? = nil, peer: String? = nil, mac: String? = nil, ok = true, msg = "", violation: String? = nil }
struct Slot: Identifiable {
    let name: String; var enabled: Bool; var ap: APInfo; var vpn: VPNInfo; var net: String; var clients: Int; var killswitch: Bool; var services: [String: Bool]; var pin: PinInfo
    var id: String { name }
    init(_ d: [String: Any]) {
        name = d["name"] as? String ?? "?"; enabled = d["enabled"] as? Bool ?? true; net = d["net"] as? String ?? ""
        clients = d["clients"] as? Int ?? 0; killswitch = (d["killswitch"] as? [String: Any])?["ok"] as? Bool ?? false
        services = d["services"] as? [String: Bool] ?? [:]
        var pi = PinInfo(); if let x = d["pin"] as? [String: Any] {
            pi.pinned = x["pinned"] as? Bool ?? false; pi.profile = x["profile"] as? String; pi.ssid = x["ssid"] as? String
            pi.peer = x["peer"] as? String; pi.mac = x["mac"] as? String; pi.ok = x["ok"] as? Bool ?? false
            pi.msg = x["msg"] as? String ?? ""; pi.violation = x["violation"] as? String }
        pin = pi
        var a = APInfo(); if let x = d["ap"] as? [String: Any] {
            a.iface = x["if"] as? String ?? ""; a.ssid = x["ssid"] as? String ?? "?"; a.up = x["up"] as? Bool ?? false
            a.channel = x["channel"] as? Int ?? 0; a.width = x["width_mhz"] as? Int ?? 0; a.band = x["band"] as? String ?? "" }
        ap = a
        var v = VPNInfo(); if let x = d["vpn"] as? [String: Any] {
            v.iface = x["if"] as? String ?? ""; v.profile = x["profile"] as? String; v.up = x["up"] as? Bool ?? false; v.healthy = x["healthy"] as? Bool ?? false
            v.endpoint = x["endpoint"] as? String ?? "-"; v.handshakeAge = x["handshake_age_s"] as? Int; v.address = x["address"] as? String ?? "-"
            v.rx = x["rx_bytes"] as? Int ?? 0; v.tx = x["tx_bytes"] as? Int ?? 0; v.mtu = x["mtu"] as? Int ?? 0 }
        vpn = v
    }
}
struct LANInfo { var iface = "-", ip = "-", gw = "-" }
struct Status {
    var slots: [Slot] = []; var lan = LANInfo(); var services: [String: Bool] = [:]
    var clients = 0; var uptime = 0; var load = 0.0; var temp: Double? = nil; var killswitch = false; var ts = Date()
    init() {}
    init(_ d: [String: Any]) {
        slots = (d["slots"] as? [[String: Any]] ?? []).map(Slot.init)
        if let l = d["lan"] as? [String: Any] { lan.iface = l["if"] as? String ?? "-"; lan.ip = l["ip"] as? String ?? "-"; lan.gw = l["gw"] as? String ?? "-" }
        services = d["services"] as? [String: Bool] ?? [:]
        clients = d["clients"] as? Int ?? 0; uptime = d["uptime_s"] as? Int ?? 0; load = d["load1"] as? Double ?? 0; temp = d["temp_c"] as? Double
        killswitch = (d["killswitch"] as? [String: Any])?["ok"] as? Bool ?? false
    }
}
struct Client: Identifiable {
    let mac: String; var slot: String, ip: String?, hostname: String?, signal: Int?, connected: Int?, rx: Int, tx: Int, txRate: Double?
    var id: String { slot + mac }
    init(_ d: [String: Any]) {
        mac = d["mac"] as? String ?? "?"; slot = d["slot"] as? String ?? "?"; ip = d["ip"] as? String; hostname = d["hostname"] as? String
        signal = d["signal_dbm"] as? Int; connected = d["connected_s"] as? Int
        rx = d["rx_bytes"] as? Int ?? 0; tx = d["tx_bytes"] as? Int ?? 0; txRate = d["tx_rate_mbps"] as? Double
    }
}
struct Profile: Identifiable {
    let name: String; var slot: String?, endpoint: String, address: String, mtu: String, type: String
    var id: String { name }
    var active: Bool { slot != nil }
    init(_ d: [String: Any]) {
        name = d["name"] as? String ?? "?"; slot = d["slot"] as? String
        endpoint = d["endpoint"] as? String ?? "-"; address = d["address"] as? String ?? "-"; mtu = d["mtu"] as? String ?? "-"; type = d["type"] as? String ?? "wireguard"
    }
}
struct WifiInfo { var slot = "", iface = "", ssid = "", psk = "", band = "", channel = 0; var loaded = false }

// MARK: - AppState
@MainActor
final class AppState: ObservableObject {
    let ble = BLEClient()
    @Published var knownDevices: Set<UUID> = []
    @Published var status = Status()
    @Published var clients: [Client] = []
    @Published var profiles: [Profile] = []
    @Published var wifi: [String: WifiInfo] = [:]          // slot -> wifi
    @Published var exitIP: [String: String] = [:]          // slot -> ip
    @Published var busy: String? = nil
    @Published var lastError: String? = nil
    @Published var piLogs: [String] = []
    @Published var verifyResult: String? = nil
    @Published var autoRefresh = true
    private var timer: Timer?
    private var bag = Set<AnyCancellable>()

    init() {
        ble.objectWillChange.receive(on: DispatchQueue.main).sink { [weak self] _ in self?.objectWillChange.send() }.store(in: &bag)
        ble.onDisconnect = { [weak self] in Task { @MainActor in self?.stopTimer() } }
    }

    var connected: Bool { ble.state == .ready }
    var slotNames: [String] { status.slots.map(\.name) }

    // token / takma ad
    func hasToken(_ id: UUID) -> Bool {
        if knownDevices.contains(id) { return true }
        if Keychain.load(device: id) != nil { knownDevices.insert(id); return true }
        return false
    }
    func setToken(_ t: String, for id: UUID) { Keychain.save(t, device: id); knownDevices.insert(id) }
    func forgetToken(_ id: UUID) { Keychain.delete(device: id); knownDevices.remove(id) }
    @Published var nicknames: [UUID: String] = {
        var d: [UUID: String] = [:]
        for (k, v) in UserDefaults.standard.dictionaryRepresentation() where k.hasPrefix("nick-") {
            if let id = UUID(uuidString: String(k.dropFirst(5))), let n = v as? String { d[id] = n }
        }
        return d
    }()
    func nickname(_ id: UUID) -> String? { nicknames[id] }
    func setNickname(_ n: String, for id: UUID) {
        let t = n.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { nicknames[id] = nil; UserDefaults.standard.removeObject(forKey: "nick-\(id.uuidString)") }
        else { nicknames[id] = t; UserDefaults.standard.set(t, forKey: "nick-\(id.uuidString)") }
    }
    func displayName(_ d: BLEClient.Found) -> String { nicknames[d.id] ?? d.name }
    @discardableResult
    func connect(_ id: UUID) -> Bool {
        guard let t = Keychain.load(device: id) else { return false }
        ble.token = t; ble.connect(id); return true
    }

    func startTimer() {
        stopTimer()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in if self?.autoRefresh == true { await self?.refreshStatus() } }
        }
    }
    func stopTimer() { timer?.invalidate(); timer = nil }

    func run(_ label: String, _ body: @escaping () async throws -> Void) {
        Task { busy = label; lastError = nil
            do { try await body() } catch { lastError = error.localizedDescription; ble.note("HATA \(label): \(error.localizedDescription)") }
            busy = nil }
    }

    // MARK: veri çekme
    func refreshStatus() async {
        guard connected else { return }
        do { status = Status(try await ble.callDict("status")) } catch { lastError = error.localizedDescription }
    }
    func refreshClients() async {
        guard connected else { return }
        do { clients = try await ble.callList("clients").map(Client.init) } catch { lastError = error.localizedDescription }
    }
    func refreshProfiles() async {
        guard connected else { return }
        do { profiles = try await ble.callList("vpn.list").map(Profile.init) } catch { lastError = error.localizedDescription }
    }
    func refreshWifi(_ slot: String) async {
        guard connected else { return }
        do {
            let w = try await ble.callDict("wifi.get", args: ["slot": slot])
            wifi[slot] = WifiInfo(slot: slot, iface: w["if"] as? String ?? "", ssid: w["ssid"] as? String ?? "", psk: w["psk"] as? String ?? "",
                                  band: w["band"] as? String ?? "", channel: w["channel"] as? Int ?? 0, loaded: true)
        } catch { lastError = error.localizedDescription }
    }
    func refreshAll() async {
        await refreshStatus(); await refreshClients(); await refreshProfiles()
        for s in slotNames { await refreshWifi(s) }
    }

    // MARK: eylemler
    func fetchExitIP(_ slot: String) {
        run("Çıkış IP (\(slot))") { self.exitIP[slot] = (try await self.ble.callDict("exitip", args: ["slot": slot], timeout: 30))["exit_ip"] as? String ?? "?" }
    }
    func kick(_ c: Client) { run("Düşür") { _ = try await self.ble.call("kick", args: ["mac": c.mac, "slot": c.slot]); await self.refreshClients() } }
    func setWifi(slot: String, ssid: String, psk: String) {
        run("Wi-Fi uygula (\(slot))") {
            let cur = self.wifi[slot] ?? WifiInfo(); var a: [String: Any] = ["slot": slot]
            if ssid != cur.ssid { a["ssid"] = ssid }; if psk != cur.psk { a["psk"] = psk }
            guard a.count > 1 else { return }
            _ = try await self.ble.call("wifi.set", args: a, timeout: 60); await self.refreshWifi(slot); await self.refreshStatus()
        }
    }
    func addProfile(name: String, conf: String, overwrite: Bool) {
        run("Profil ekle") { _ = try await self.ble.call("vpn.add", args: ["name": name, "conf": conf, "overwrite": overwrite], timeout: 90); await self.refreshProfiles() }
    }
    /// Yayın–VPN eşlemesini değiştiren işlemler için Pi'nin beklediği yazılı onay: etkilenen yayınların SSID'leri " / " ile.
    func ssid(of slot: String) -> String { status.slots.first { $0.name == slot }?.ap.ssid ?? slot }
    func confirmText(_ slots: [String]) -> String { slots.map(ssid(of:)).joined(separator: " / ") }

    func activateProfile(_ name: String, slot: String, force: Bool = false, confirm: String) {
        run("\(slot) → \(name)") {
            let r = try await self.ble.callDict("vpn.activate", args: ["name": name, "slot": slot, "force": force, "confirm": confirm], timeout: 240)
            self.verifyResult = (r["summary"] as? [String])?.joined(separator: "\n")
            await self.refreshProfiles(); await self.refreshStatus(); self.exitIP = [:]
        }
    }
    /// İki yayının tünellerini takas et (Pi sırayla: B'yi kopar → A'ya B'nin profili → B'ye A'nın profili).
    func swapSlots(_ a: String, _ b: String, confirm: String) {
        run("\(a) ⇄ \(b) takas") {
            let r = try await self.ble.callDict("vpn.swap", args: ["slot_a": a, "slot_b": b, "confirm": confirm], timeout: 400)
            self.verifyResult = (r["summary"] as? [String])?.joined(separator: "\n")
            await self.refreshProfiles(); await self.refreshStatus(); self.exitIP = [:]
        }
    }
    /// Slotun MEVCUT durumunu sabit olarak kaydet (ihlal sonrası, durum doğrulandıysa) ve yayını başlat.
    func pinSlot(_ slot: String, confirm: String) {
        run("\(slot) sabitle") {
            let r = try await self.ble.callDict("slot.pin", args: ["slot": slot, "confirm": confirm], timeout: 60)
            self.verifyResult = "Sabitlendi: \(r["msg"] as? String ?? "")"
            await self.refreshStatus()
        }
    }
    func removeProfile(_ name: String) { run("Profil sil") { _ = try await self.ble.call("vpn.remove", args: ["name": name]); await self.refreshProfiles() } }
    func setSlotEnabled(_ slot: String, _ on: Bool) {
        run(on ? "\(slot) yayını aç" : "\(slot) yayını kapat") {
            _ = try await self.ble.call(on ? "slot.enable" : "slot.disable", args: ["slot": slot], timeout: 90); await self.refreshStatus()
        }
    }
    func verify() {
        run("Doğrulama") {
            let r = try await self.ble.callDict("verify", timeout: 200)
            let fails = (r["failures"] as? [String]) ?? []
            self.verifyResult = "\(r["pass"] ?? "?") PASS / \(r["fail"] ?? "?") FAIL" + (fails.isEmpty ? "" : "\n" + fails.joined(separator: "\n"))
        }
    }
    func fetchLogs(lines: Int = 80) { run("Günlük") { self.piLogs = (try await self.ble.callDict("logs", args: ["lines": lines]))["lines"] as? [String] ?? [] } }
    func firewall() { run("Firewall") { _ = try await self.ble.call("firewall", timeout: 60); await self.refreshStatus() } }
    func reboot() { run("Yeniden başlat") { _ = try await self.ble.call("reboot"); self.ble.disconnect() } }
}

func fmtBytes(_ b: Int) -> String {
    let u = ["B", "KB", "MB", "GB"]; var v = Double(b); var i = 0
    while v >= 1024 && i < u.count - 1 { v /= 1024; i += 1 }
    return String(format: i == 0 ? "%.0f %@" : "%.1f %@", v, u[i])
}
func fmtDur(_ s: Int) -> String {
    if s < 60 { return "\(s)s" }; if s < 3600 { return "\(s/60)dk" }
    if s < 86400 { return "\(s/3600)sa \(s%3600/60)dk" }; return "\(s/86400)g \(s%86400/3600)sa"
}
