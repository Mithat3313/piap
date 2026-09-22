import SwiftUI

enum Section: String, CaseIterable, Identifiable {
    case status = "Yayınlar", clients = "İstemciler", wifi = "Wi-Fi", vpn = "VPN", logs = "Günlük"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .status: return "antenna.radiowaves.left.and.right"
        case .clients: return "iphone.gen3.radiowaves.left.and.right"
        case .wifi: return "wifi"
        case .vpn: return "lock.shield"
        case .logs: return "doc.text.magnifyingglass"
        }
    }
}

/// Kapı: bağlı değilken SADECE bağlantı ekranı. Bağlanınca ana arayüz. Kopunca geri.
struct ContentView: View {
    @EnvironmentObject var app: AppState
    var body: some View {
        Group { if app.connected { MainView() } else { ConnectView() } }
            .onChange(of: app.ble.state) { _, s in if s == .ready { Task { await app.refreshAll(); app.startTimer() } } }
            .animation(.easeInOut(duration: 0.2), value: app.connected)
    }
}

// MARK: - Ana arayüz (sadece bağlıyken)
struct MainView: View {
    @EnvironmentObject var app: AppState
    @State private var section: Section = .status

    var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $section) { s in Label(s.rawValue, systemImage: s.icon).tag(s) }
                .navigationSplitViewColumnWidth(min: 170, ideal: 190)
                .safeAreaInset(edge: .bottom) { footer }
        } detail: {
            Group {
                switch section {
                case .status: SlotsView()
                case .clients: ClientsView()
                case .wifi: WiFiView()
                case .vpn: VPNView()
                case .logs: LogsView()
                }
            }
            .frame(minWidth: 560, minHeight: 420)
        }
        .overlay(alignment: .bottom) {
            if let e = app.lastError {
                Text(e).font(.callout).padding(10).background(.red.opacity(0.9)).foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 8)).padding().onTapGesture { app.lastError = nil }
            }
        }
    }

    var footer: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Circle().fill(.green).frame(width: 8, height: 8)
                Text(app.ble.connectedID.flatMap { app.nickname($0) } ?? app.ble.peripheralName).font(.caption).bold(); Spacer()
                Image(systemName: "lock.fill").font(.caption2).foregroundStyle(.green).help("Uçtan uca şifreli oturum (v2)")
                Text("MTU \(app.ble.mtu)").font(.caption2).foregroundStyle(.secondary)
            }
            if let b = app.busy { HStack(spacing: 6) { ProgressView().controlSize(.mini); Text(b).font(.caption2).lineLimit(1) } }
            Button("Bağlantıyı kes", role: .destructive) { app.ble.disconnect() }.controlSize(.small).frame(maxWidth: .infinity)
        }
        .padding(10).background(.bar)
    }
}

// MARK: - Bağlantı kapısı
struct ConnectView: View {
    @EnvironmentObject var app: AppState
    @State private var connectingID: UUID? = nil
    @State private var tokenPrompt: BLEClient.Found? = nil     // anahtar sorulacak cihaz
    @State private var promptMessage: String? = nil
    @State private var namePrompt: BLEClient.Found? = nil

    private var scanning: Bool { app.ble.state == .scanning }
    private var inProgress: Bool {
        switch app.ble.state { case .connecting, .discovering, .pairing, .authenticating: return true; default: return false }
    }

    var body: some View {
        VStack(spacing: 22) {
            VStack(spacing: 6) {
                Image(systemName: "antenna.radiowaves.left.and.right.circle.fill").font(.system(size: 52)).foregroundStyle(.tint)
                Text("PiAP Manager").font(.title).bold()
                Text("Yakındaki Raspberry Pi erişim noktasını seçin. Her cihazın kendi erişim anahtarı vardır; ilk bağlantıda sorulur, sonra hatırlanır.")
                    .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 460)
            }

            GroupBox {
                VStack(spacing: 8) {
                    if app.ble.found.isEmpty {
                        HStack(spacing: 10) {
                            if scanning || app.ble.state == .starting { ProgressView().controlSize(.small) }
                            Text(scanning ? "Aranıyor… Pi'nin açık ve 10 m içinde olması gerekir."
                                          : app.ble.state == .starting ? "Bluetooth hazırlanıyor…"
                                          : app.ble.state == .off ? "Bluetooth kapalı." : "Cihaz bulunamadı.")
                                .foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, minHeight: 60)
                    } else {
                        ForEach(app.ble.found) { d in deviceRow(d) }
                    }
                }
            } label: {
                HStack {
                    Text("Cihazlar"); Spacer()
                    Button(scanning ? "Durdur" : "Yeniden tara") { scanning ? app.ble.stopScan() : app.ble.startScan() }
                        .controlSize(.small).disabled(inProgress)
                }
            }

            if case .error(let e) = app.ble.state {
                Label(e, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.callout)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Spacer(minLength: 0)
        }
        .padding(28)
        .frame(minWidth: 540, idealWidth: 580, minHeight: 460)
        .onAppear { connectingID = nil; if !scanning { app.ble.startScan() } }
        .onChange(of: app.ble.state) { _, s in
            if s == .idle { connectingID = nil; app.ble.startScan() }
            if case .error(let e) = s, e.contains("token"), let id = connectingID, let d = app.ble.found.first(where: { $0.id == id }) {
                // yanlış anahtar → aynı cihaz için tekrar sor
                promptMessage = "Anahtar reddedildi. Bu cihazın anahtarını yeniden girin."
                tokenPrompt = d
            }
        }
        .sheet(item: $tokenPrompt) { d in
            TokenSheet(device: d, message: promptMessage, initialName: app.nickname(d.id) ?? "") { token, name in
                app.setNickname(name, for: d.id)
                app.setToken(token, for: d.id); connectingID = d.id; app.connect(d.id)
            }
        }
        .sheet(item: $namePrompt) { d in
            NameSheet(device: d, initial: app.nickname(d.id) ?? "") { app.setNickname($0, for: d.id) }
        }
    }

    @ViewBuilder
    func deviceRow(_ d: BLEClient.Found) -> some View {
        let known = app.hasToken(d.id)
        let active = connectingID == d.id && inProgress
        Button {
            guard !inProgress else { return }
            connectingID = d.id; promptMessage = nil
            if !app.connect(d.id) { tokenPrompt = d }        // anahtar yoksa sor
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "dot.radiowaves.left.and.right").font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(app.displayName(d)).font(.headline)
                        if app.nickname(d.id) != nil { Text(d.name).font(.caption).foregroundStyle(.secondary) }
                        if known { Image(systemName: "key.fill").font(.caption).foregroundStyle(.green).help("Anahtar kayıtlı") }
                        else { Text("anahtar gerekli").font(.caption2).padding(.horizontal, 5).background(.orange.opacity(0.2)).clipShape(Capsule()) }
                    }
                    Text(d.id.uuidString).font(.caption2).foregroundStyle(.secondary).monospaced()
                }
                Spacer()
                if active {
                    ProgressView().controlSize(.small)
                    Text(app.ble.state.label).font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("\(d.rssi) dBm").monospacedDigit().foregroundStyle(d.rssi > -70 ? .green : .orange)
                    Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                }
            }
            .padding(10).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary.opacity(0.5)))
        .disabled(inProgress)
        .contextMenu {
            Button("Ad ver / değiştir…") { namePrompt = d }
            Button("Anahtarı değiştir…") { promptMessage = nil; tokenPrompt = d }
            if known { Button("Anahtarı unut", role: .destructive) { app.forgetToken(d.id) } }
        }
    }
}

/// Cihaza özel erişim anahtarı girişi.
struct TokenSheet: View {
    let device: BLEClient.Found
    let message: String?
    var initialName: String = ""
    let onSubmit: (String, String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var token = ""
    @State private var name = ""
    @State private var show = false
    private var valid: Bool { token.count == 64 && token.allSatisfy { $0.isHexDigit } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "key.horizontal.fill").font(.title).foregroundStyle(.tint)
                VStack(alignment: .leading) {
                    Text("\(device.name) için erişim anahtarı").font(.headline)
                    Text(device.id.uuidString).font(.caption2).monospaced().foregroundStyle(.secondary)
                }
            }
            if let m = message { Label(m, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.callout) }
            TextField("Takma ad (isteğe bağlı) — örn. Ev Pi, Ofis Pi", text: $name).textFieldStyle(.roundedBorder)
                .onAppear { name = initialName }
            HStack {
                Group { if show { TextField("64 karakter hex", text: $token) } else { SecureField("64 karakter hex", text: $token) } }
                    .textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced))
                    .onSubmit { if valid { submit() } }
                Button(show ? "Gizle" : "Göster") { show.toggle() }
            }
            Text("Anahtarı Pi'de bir kez alın: `sudo ap-ctl ble token`. Bu Mac'te Keychain'de yalnızca bu cihaz için saklanır; Bluetooth'tan hiç geçmez (sadece HMAC imzası gider).")
                .font(.caption).foregroundStyle(.secondary)
            if !token.isEmpty && !valid { Text("64 hex karakter olmalı (şu an \(token.count)).").font(.caption).foregroundStyle(.orange) }
            HStack { Spacer(); Button("Vazgeç") { dismiss() }.keyboardShortcut(.cancelAction)
                     Button("Kaydet ve bağlan") { submit() }.keyboardShortcut(.defaultAction).disabled(!valid) }
        }
        .padding(20).frame(width: 520)
    }
    private func submit() { onSubmit(token.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), name); dismiss() }
}

/// Sadece takma ad düzenleme.
struct NameSheet: View {
    let device: BLEClient.Found
    let initial: String
    let onSubmit: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("\(device.name) için takma ad").font(.headline)
            Text(device.id.uuidString).font(.caption2).monospaced().foregroundStyle(.secondary)
            TextField("örn. Ev Pi, Ofis Pi (boş = kaldır)", text: $name).textFieldStyle(.roundedBorder)
                .onAppear { name = initial }.onSubmit { onSubmit(name); dismiss() }
            HStack { Spacer(); Button("Vazgeç") { dismiss() }.keyboardShortcut(.cancelAction)
                     Button("Kaydet") { onSubmit(name); dismiss() }.keyboardShortcut(.defaultAction) }
        }.padding(20).frame(width: 420)
    }
}
