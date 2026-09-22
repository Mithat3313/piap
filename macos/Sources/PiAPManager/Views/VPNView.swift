import SwiftUI
import UniformTypeIdentifiers

struct VPNView: View {
    @EnvironmentObject var app: AppState
    @State private var showImporter = false
    @State private var newName = ""; @State private var newConf = ""; @State private var overwrite = false
    @State private var confirmActivate: (profile: String, slot: String)? = nil
    @State private var typed = ""
    var activateExpected: String { confirmActivate.map { app.ssid(of: $0.slot) } ?? "" }
    @State private var confirmRemove: Profile? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            List {
                SwiftUI.Section("Profiles (\(app.profiles.count)) — each profile can be used on at most one SSID") {
                    if app.profiles.isEmpty { Text("No profiles").foregroundStyle(.secondary) }
                    ForEach(app.profiles) { p in
                        HStack {
                            Image(systemName: p.active ? "checkmark.circle.fill" : "circle").foregroundStyle(p.active ? .green : .secondary)
                            VStack(alignment: .leading) {
                                HStack { Text(p.name).bold(); Text(p.type).font(.caption2).padding(.horizontal, 5).background(.quaternary).clipShape(Capsule()) }
                                Text("\(p.endpoint) · \(p.address) · MTU \(p.mtu)").font(.caption).monospaced().foregroundStyle(.secondary)
                            }
                            Spacer()
                            if let s = p.slot {
                                Text("→ \(s)").font(.caption).bold().foregroundStyle(.green).monospaced()
                            } else {
                                Menu("Assign to an SSID") {
                                    ForEach(app.status.slots) { s in
                                        Button("\(s.name) — \(s.ap.ssid) (currently: \(s.vpn.profile ?? "none"))") { confirmActivate = (p.name, s.name) }
                                    }
                                }.fixedSize().disabled(app.busy != nil)
                                Button(role: .destructive) { confirmRemove = p } label: { Image(systemName: "trash") }.controlSize(.small)
                            }
                        }.padding(.vertical, 2)
                    }
                }
                SwiftUI.Section("Add a new profile (WireGuard .conf)") {
                    HStack {
                        TextField("Profile name (letters/digits/-/_)", text: $newName).textFieldStyle(.roundedBorder).frame(maxWidth: 220)
                        Button("Choose a file…") { showImporter = true }
                        Toggle("Overwrite", isOn: $overwrite).toggleStyle(.checkbox)
                        Spacer()
                        Button("Send to the Pi") { app.addProfile(name: newName, conf: newConf, overwrite: overwrite); newConf = ""; newName = "" }
                            .disabled(newName.isEmpty || newConf.isEmpty || app.busy != nil)
                    }
                    TextEditor(text: $newConf).font(.system(.caption, design: .monospaced)).frame(minHeight: 120)
                        .overlay(alignment: .topLeading) {
                            if newConf.isEmpty { Text("[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\nPublicKey = …\nEndpoint = host:port\nAllowedIPs = 0.0.0.0/0").font(.system(.caption, design: .monospaced)).foregroundStyle(.tertiary).padding(6).allowsHitTesting(false) }
                        }
                    Text("The Pi sanitises the config (DNS/Table/PostUp are stripped, `Table = off` is enforced) and validates it with the kernel. When it is assigned to an SSID and no handshake arrives within 40 s, the previous profile is restored.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            HStack {
                Button("Refresh") { Task { await app.refreshProfiles(); await app.refreshStatus() } }
                if let b = app.busy { ProgressView().controlSize(.small); Text(b).font(.caption) }
                Spacer()
                if let v = app.verifyResult, !v.isEmpty { Text(v).font(.system(.caption2, design: .monospaced)).lineLimit(3).frame(maxWidth: 420, alignment: .trailing) }
            }.padding()
        }
        .navigationTitle("VPN")
        .task { await app.refreshProfiles() }
        .fileImporter(isPresented: $showImporter, allowedContentTypes: [UTType(filenameExtension: "conf") ?? .plainText, .plainText, .data]) { r in
            if case .success(let url) = r {
                let ok = url.startAccessingSecurityScopedResource(); defer { if ok { url.stopAccessingSecurityScopedResource() } }
                if let s = try? String(contentsOf: url, encoding: .utf8) {
                    newConf = s
                    if newName.isEmpty { newName = url.deletingPathExtension().lastPathComponent.replacingOccurrences(of: "[^A-Za-z0-9_-]", with: "-", options: .regularExpression) }
                }
            }
        }
        .alert("Switch \(confirmActivate?.slot ?? "") to the profile \(confirmActivate?.profile ?? "")?",
               isPresented: Binding(get: { confirmActivate != nil }, set: { if !$0 { confirmActivate = nil; typed = "" } })) {
            TextField(activateExpected, text: $typed)
            Button("Switch") { if let c = confirmActivate { app.activateProfile(c.profile, slot: c.slot, confirm: typed.trimmingCharacters(in: .whitespaces)) }; confirmActivate = nil; typed = "" }
                .disabled(typed.trimmingCharacters(in: .whitespaces) != activateExpected)
            Button("Cancel", role: .cancel) { confirmActivate = nil; typed = "" }
        } message: { Text("That SSID's tunnel is rebuilt; its clients lose connectivity for a few seconds (nothing leaks). This can take 1-2 minutes.\n\nThis operation changes the SSID-VPN mapping. To confirm, type exactly:\n\(activateExpected)") }
        .confirmationDialog("\(confirmRemove?.name ?? "") silinsin mi?", isPresented: Binding(get: { confirmRemove != nil }, set: { if !$0 { confirmRemove = nil } })) {
            Button("Delete", role: .destructive) { if let p = confirmRemove { app.removeProfile(p.name) }; confirmRemove = nil }
        }
    }
}

struct LogsView: View {
    @EnvironmentObject var app: AppState
    @State private var tab = 0
    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $tab) { Text("Pi log").tag(0); Text("Bluetooth (local)").tag(1) }.pickerStyle(.segmented).padding()
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(Array((tab == 0 ? app.piLogs : app.ble.log).enumerated()), id: \.offset) { i, l in
                            Text(l).font(.system(.caption, design: .monospaced)).textSelection(.enabled).id(i)
                        }
                    }.padding(.horizontal)
                }
                .onChange(of: app.ble.log.count) { _, n in if tab == 1 { proxy.scrollTo(n - 1) } }
            }
            HStack {
                if tab == 0 { Button("Fetch the Pi log") { app.fetchLogs() } }
                else { Button("Temizle") { app.ble.log.removeAll() }; Text("~/Library/Logs/PiAPManager.log").font(.caption).foregroundStyle(.secondary) }
                Spacer()
            }.padding()
        }
        .navigationTitle("Log")
    }
}
