import SwiftUI

// MARK: - SSIDs (main screen): each slot = one radio + one tunnel
struct SlotsView: View {
    @EnvironmentObject var app: AppState
    @State private var confirmReboot = false
    @State private var pendingActivate: (slot: String, profile: String, stealFrom: String?)? = nil
    @State private var pendingSwap: (a: String, b: String)? = nil
    @State private var pendingToggle: (slot: String, on: Bool)? = nil
    @State private var pendingPin: String? = nil
    @State private var typed = ""          // typed confirmation (also enforced on the Pi; guards against a mis-click)
    var s: Status { app.status }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if s.slots.isEmpty { ProgressView("Loading status…").frame(maxWidth: .infinity, minHeight: 120) }
                ForEach(s.slots) { slot in slotCard(slot) }
                globalCard
                HStack {
                    Button("Refresh") { Task { await app.refreshAll() } }
                    Toggle("Auto (5 s)", isOn: $app.autoRefresh).toggleStyle(.checkbox)
                    Button("Full verification") { app.verify() }
                    Button("Re-apply firewall") { app.firewall() }
                    Spacer()
                    Button("Reboot", role: .destructive) { confirmReboot = true }
                }
                if let v = app.verifyResult {
                    GroupBox("Last verification / activation") { Text(v).font(.system(.caption, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading) }
                }
                Text("Last update: \(s.ts.formatted(date: .omitted, time: .standard))").font(.caption2).foregroundStyle(.secondary)
            }
            .padding()
        }
        .navigationTitle("SSIDs")
        .confirmationDialog("Reboot the Pi?", isPresented: $confirmReboot) {
            Button("Reboot", role: .destructive) { app.reboot() }
        } message: { Text("Every SSID, every tunnel and the other services on the Pi stay down for ~1-2 minutes. The Bluetooth connection drops.") }
        // ASSIGNMENT PINNING: every operation that changes the mapping requires the affected SSIDs to be typed verbatim.
        .alert("Switch \(pendingActivate?.slot ?? "") to the profile \(pendingActivate?.profile ?? "")?",
               isPresented: Binding(get: { pendingActivate != nil }, set: { if !$0 { pendingActivate = nil; typed = "" } })) {
            TextField(activateExpected, text: $typed)
            Button(pendingActivate?.stealFrom != nil ? "Take and switch" : "Switch") {
                if let p = pendingActivate { app.activateProfile(p.profile, slot: p.slot, force: p.stealFrom != nil, confirm: typed.trimmingCharacters(in: .whitespaces)) }
                pendingActivate = nil; typed = ""
            }.disabled(typed.trimmingCharacters(in: .whitespaces) != activateExpected)
            Button("Cancel", role: .cancel) { pendingActivate = nil; typed = "" }
        } message: {
            if let from = pendingActivate?.stealFrom {
                Text("⚠️ \(pendingActivate?.profile ?? "") is currently on \(from). It will be taken from there: \(from) stays WITHOUT A TUNNEL until you assign a new profile (the kill switch holds). This SSID's tunnel is rebuilt.\n\nThis operation changes the SSID-VPN mapping. To confirm, type exactly:\n\(activateExpected)")
            } else {
                Text("This SSID's tunnel is rebuilt; its clients lose connectivity for a few seconds (nothing leaks). If no handshake arrives, the previous profile is restored.\n\nThis operation changes the SSID-VPN mapping. To confirm, type exactly:\n\(activateExpected)")
            }
        }
        .alert("Swap the tunnels of \(pendingSwap?.a ?? "") ⇄ \(pendingSwap?.b ?? "")?",
               isPresented: Binding(get: { pendingSwap != nil }, set: { if !$0 { pendingSwap = nil; typed = "" } })) {
            TextField(swapExpected, text: $typed)
            Button("Swap") { if let sw = pendingSwap { app.swapSlots(sw.a, sw.b, confirm: typed.trimmingCharacters(in: .whitespaces)) }; pendingSwap = nil; typed = "" }
                .disabled(typed.trimmingCharacters(in: .whitespaces) != swapExpected)
            Button("Cancel", role: .cancel) { pendingSwap = nil; typed = "" }
        } message: {
            if let sw = pendingSwap {
                Text("\(app.ssid(of: sw.a)) → \(s.slots.first { $0.name == sw.b }?.vpn.profile ?? "—")\n\(app.ssid(of: sw.b)) → \(s.slots.first { $0.name == sw.a }?.vpn.profile ?? "—")\nClients of both SSIDs lose connectivity briefly. This can take 1-3 minutes.\n\nThis operation changes the SSID-VPN mapping. To confirm, type exactly:\n\(swapExpected)")
            }
        }
        .alert("Re-pin \(pendingPin ?? "")?",
               isPresented: Binding(get: { pendingPin != nil }, set: { if !$0 { pendingPin = nil; typed = "" } })) {
            TextField(pinExpected, text: $typed)
            Button("Pin and start the SSID") { if let p = pendingPin { app.pinSlot(p, confirm: typed.trimmingCharacters(in: .whitespaces)) }; pendingPin = nil; typed = "" }
                .disabled(typed.trimmingCharacters(in: .whitespaces) != pinExpected)
            Button("Cancel", role: .cancel) { pendingPin = nil; typed = "" }
        } message: {
            if let p = pendingPin {
                Text("The CURRENT state of this SSID (SSID, profile, server key, radio MAC) is stored as the pin.\nRight now: \(app.ssid(of: p)) → \(s.slots.first { $0.name == p }?.vpn.profile ?? "—")\nIf you did not make this change, investigate first.\n\nTo confirm, type exactly:\n\(pinExpected)")
            }
        }
        .confirmationDialog("Turn \(pendingToggle?.slot ?? "") \(pendingToggle?.on == true ? "on" : "off")?",
                            isPresented: Binding(get: { pendingToggle != nil }, set: { if !$0 { pendingToggle = nil } })) {
            Button(pendingToggle?.on == true ? "Turn on" : "Turn off", role: pendingToggle?.on == true ? nil : .destructive) {
                if let t = pendingToggle { app.setSlotEnabled(t.slot, t.on) }; pendingToggle = nil
            }
        } message: { Text(pendingToggle?.on == true ? "The SSID goes on the air and the tunnel is brought up." : "The SSID goes down, connected clients are dropped and the tunnel is stopped. The other SSID is unaffected.") }
    }

    var activateExpected: String { pendingActivate.map { app.confirmText([$0.slot] + ($0.stealFrom.map { [$0] } ?? [])) } ?? "" }
    var swapExpected: String { pendingSwap.map { app.confirmText([$0.a, $0.b]) } ?? "" }
    var pinExpected: String { pendingPin.map { app.ssid(of: $0) } ?? "" }

    @ViewBuilder
    func slotCard(_ slot: Slot) -> some View {
        let healthy = slot.enabled && slot.ap.up && slot.vpn.healthy && slot.killswitch && slot.pin.ok
        GroupBox {
          VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 18) {
                // radio
                VStack(alignment: .leading, spacing: 5) {
                    Label("Wi-Fi", systemImage: "wifi").font(.caption).foregroundStyle(.secondary)
                    Text(slot.ap.ssid).font(.title3).bold()
                    Text("\(slot.ap.band) · kanal \(slot.ap.channel) · \(slot.ap.width) MHz · \(slot.ap.iface)").font(.caption).monospaced().foregroundStyle(.secondary)
                    HStack(spacing: 6) {
                        Circle().fill(slot.ap.up ? .green : .red).frame(width: 8, height: 8)
                        Text(slot.ap.up ? "on the air" : "DOWN").font(.callout)
                        Text("· \(slot.clients) clients · \(slot.net)").font(.callout).foregroundStyle(.secondary)
                    }
                }
                .frame(minWidth: 220, alignment: .leading)
                Divider()
                // tunnel
                VStack(alignment: .leading, spacing: 5) {
                    Label("VPN exit", systemImage: "lock.shield").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Menu {
                            ForEach(app.profiles) { p in
                                Button {
                                    if p.slot != slot.name { pendingActivate = (slot.name, p.name, p.slot) }
                                } label: {
                                    HStack { Text(p.name); if let s = p.slot { Text(s == slot.name ? "(this SSID)" : "— taken from \(s)") } }
                                }.disabled(p.slot == slot.name)
                            }
                            if s.slots.count == 2, let other = s.slots.first(where: { $0.name != slot.name }) {
                                Divider()
                                Button("⇄ swap with \(other.name)") { pendingSwap = (slot.name, other.name) }
                            }
                        } label: {
                            Text(slot.vpn.profile ?? "select a profile").bold()
                        }
                        .menuStyle(.borderlessButton).fixedSize()
                        .disabled(app.busy != nil || !slot.enabled)
                        Circle().fill(slot.vpn.healthy ? .green : .red).frame(width: 8, height: 8)
                        Text(slot.vpn.healthy ? "handshake \(fmtDur(slot.vpn.handshakeAge ?? 0)) ago" : "no tunnel").font(.caption).foregroundStyle(.secondary)
                    }
                    Text("\(slot.vpn.endpoint) · \(slot.vpn.iface) \(slot.vpn.address)").font(.caption).monospaced().foregroundStyle(.secondary)
                    Text("↓\(fmtBytes(slot.vpn.rx)) ↑\(fmtBytes(slot.vpn.tx))").font(.caption).foregroundStyle(.secondary)
                    HStack(spacing: 8) {
                        Text("Exit IP:").font(.callout).foregroundStyle(.secondary)
                        Text(app.exitIP[slot.name] ?? "—").font(.callout).monospaced().bold()
                        Button("Query") { app.fetchExitIP(slot.name) }.controlSize(.small).disabled(app.busy != nil || !slot.vpn.up)
                    }
                }
                .frame(minWidth: 260, alignment: .leading)
                Spacer()
                VStack(alignment: .trailing, spacing: 8) {
                    Toggle("SSID", isOn: Binding(get: { slot.enabled }, set: { pendingToggle = (slot.name, $0) }))
                        .toggleStyle(.switch).controlSize(.small).disabled(app.busy != nil)
                    HStack(spacing: 4) {
                        Image(systemName: slot.killswitch ? "checkmark.shield.fill" : "xmark.shield.fill").foregroundStyle(slot.killswitch ? .green : .red)
                        Text("killswitch").font(.caption2)
                    }
                    HStack(spacing: 4) {
                        Image(systemName: slot.pin.ok ? (slot.pin.pinned ? "lock.fill" : "lock.open") : "exclamationmark.lock.fill").foregroundStyle(slot.pin.ok ? (slot.pin.pinned ? .green : .orange) : .red)
                        Text(slot.pin.ok ? (slot.pin.pinned ? "pinned: \(slot.pin.profile ?? "")" : "not pinned") : "PIN VIOLATION").font(.caption2)
                    }.help(slot.pin.msg)
                }
            }
            if !slot.pin.ok {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("ASSIGNMENT VIOLATION — the SSID was stopped (fail-closed).").bold().foregroundStyle(.red)
                        Text(slot.pin.violation ?? slot.pin.msg).font(.caption).monospaced()
                        Text("If you did not make this change, investigate first. If the current state is correct, re-pin it.").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Re-pin") { pendingPin = slot.name }.controlSize(.small).disabled(app.busy != nil)
                }
                .padding(8).background(Color.red.opacity(0.08)).clipShape(RoundedRectangle(cornerRadius: 6))
            }
          }
        } label: {
            HStack { Circle().fill(healthy ? .green : (slot.enabled ? .orange : .gray)).frame(width: 10, height: 10); Text(slot.name).bold().monospaced()
                     Text(healthy ? "healthy" : (slot.enabled ? "problem" : "off")).font(.caption).foregroundStyle(.secondary) }
        }
    }

    var globalCard: some View {
        GroupBox {
            HStack(spacing: 24) {
                row("LAN", "\(s.lan.iface) \(s.lan.ip)"); row("Gateway", s.lan.gw)
                row("Uptime", fmtDur(s.uptime)); row("Load", String(format: "%.2f", s.load))
                row("Temp", s.temp.map { String(format: "%.1f°C", $0) } ?? "-")
                Spacer()
                ForEach(s.services.keys.sorted(), id: \.self) { k in
                    HStack(spacing: 4) { Circle().fill(s.services[k] == true ? .green : .red).frame(width: 7, height: 7); Text(k).font(.caption2).monospaced() }
                }
            }
        } label: { HStack { Circle().fill(s.services.values.allSatisfy { $0 } ? .green : .red).frame(width: 9, height: 9); Text("Pi").bold() } }
    }
    func row(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 2) { Text(k).font(.caption2).foregroundStyle(.secondary); Text(v).font(.callout).monospacedDigit() }
    }
}

// MARK: - Clients
struct ClientsView: View {
    @EnvironmentObject var app: AppState
    var body: some View {
        VStack(alignment: .leading) {
            if app.clients.isEmpty {
                ContentUnavailableView("No connected clients", systemImage: "iphone.slash", description: Text("Devices that join the SSIDs appear here."))
            } else {
                Table(app.clients) {
                    TableColumn("SSID") { c in Text(c.slot).monospaced() }.width(50)
                    TableColumn("Device") { c in Text(c.hostname ?? "—") }
                    TableColumn("IP") { c in Text(c.ip ?? "—").monospaced() }
                    TableColumn("MAC") { c in Text(c.mac).monospaced().font(.caption) }
                    TableColumn("Signal") { c in Text(c.signal.map { "\($0) dBm" } ?? "—").foregroundStyle((c.signal ?? -100) > -65 ? .green : .orange) }
                    TableColumn("Rate") { c in Text(c.txRate.map { String(format: "%.0f Mbps", $0) } ?? "—") }
                    TableColumn("Connected") { c in Text(c.connected.map(fmtDur) ?? "—") }
                    TableColumn("Trafik") { c in Text("↓\(fmtBytes(c.tx)) ↑\(fmtBytes(c.rx))").font(.caption) }
                    TableColumn("") { c in Button("Kick") { app.kick(c) }.controlSize(.small) }.width(60)
                }
            }
            HStack { Button("Refresh") { Task { await app.refreshClients() } }; Text("\(app.clients.count) clients").foregroundStyle(.secondary) }.padding()
        }
        .navigationTitle("Clients")
        .task { await app.refreshClients() }
    }
}

// MARK: - Wi-Fi (per slot)
struct WiFiView: View {
    @EnvironmentObject var app: AppState
    @State private var slot = ""
    @State private var ssid = ""; @State private var psk = ""
    @State private var showPsk = false; @State private var confirm = false; @State private var copied = false

    private var cur: WifiInfo { app.wifi[slot] ?? WifiInfo() }
    private var ssidValid: Bool { (1...32).contains(ssid.utf8.count) && !ssid.contains(where: { $0 == "\n" || $0 == "\r" }) }
    private var pskValid: Bool { (8...63).contains(psk.count) && psk.allSatisfy { $0.isASCII && ($0.asciiValue ?? 0) >= 32 && ($0.asciiValue ?? 0) <= 126 } }
    private var changed: Bool { ssid != cur.ssid || psk != cur.psk }

    var body: some View {
        Form {
            SwiftUI.Section {
                Picker("SSID", selection: $slot) {
                    ForEach(app.status.slots) { s in Text("\(s.name) — \(s.ap.ssid) (\(s.ap.band))").tag(s.name) }
                }.pickerStyle(.segmented)
            }
            SwiftUI.Section {
                TextField("Network name (SSID)", text: $ssid).textFieldStyle(.roundedBorder)
                if !ssidValid && !ssid.isEmpty { note("The SSID must be 1-32 bytes (currently \(ssid.utf8.count)).", .red) }
                else if ssidValid && !ssid.hasSuffix("_nomap") { note("Ending with `_nomap` is recommended: phones then do not report this AP to the Google/Apple positioning databases.", .orange) }
                HStack {
                    Group { if showPsk { TextField("Password", text: $psk) } else { SecureField("Password", text: $psk) } }
                        .textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced))
                    Button { showPsk.toggle() } label: { Image(systemName: showPsk ? "eye.slash" : "eye") }.help(showPsk ? "Hide" : "Show")
                    Button {
                        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(psk, forType: .string)
                        copied = true; DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: { Image(systemName: copied ? "checkmark" : "doc.on.doc") }.help("Copy the password").disabled(psk.isEmpty)
                }
                if !pskValid && !psk.isEmpty { note("The password must be 8-63 printable ASCII characters (currently \(psk.count)).", .red) }
            } header: { Text("Guest network — \(slot)") } footer: {
                Text("Applying restarts only this SSID's hostapd; its clients are dropped. The other SSID and Bluetooth are unaffected.")
            }
            SwiftUI.Section("Radio") {
                LabeledContent("Interface", value: cur.iface.isEmpty ? "—" : cur.iface)
                LabeledContent("Band / channel", value: cur.band.isEmpty ? "—" : "\(cur.band) · channel \(cur.channel)")
                LabeledContent("VPN exit", value: app.status.slots.first { $0.name == slot }?.vpn.profile ?? "—")
            }
            SwiftUI.Section {
                HStack {
                    Button("Apply") { confirm = true }.keyboardShortcut(.defaultAction)
                        .disabled(!changed || !ssidValid || !pskValid || app.busy != nil || !cur.loaded)
                    Button("Cancel") { load() }.disabled(!changed)
                    Spacer()
                    if app.busy != nil { ProgressView().controlSize(.small) }
                    else if changed { Text("Unsaved changes").font(.caption).foregroundStyle(.orange) }
                    else if cur.loaded { Text("Up to date").font(.caption).foregroundStyle(.secondary) }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Wi-Fi")
        .task { if slot.isEmpty { slot = app.slotNames.first ?? "" }; await app.refreshWifi(slot); load() }
        .onChange(of: slot) { _, s in Task { await app.refreshWifi(s); load() } }
        .onChange(of: cur.loaded) { _, _ in if !changed { load() } }
        .confirmationDialog("Apply the Wi-Fi settings of \(slot)?", isPresented: $confirm) {
            Button("Apply") { app.setWifi(slot: slot, ssid: ssid, psk: psk) }
        } message: { Text(summary()) }
    }
    private func load() { ssid = cur.ssid; psk = cur.psk }
    private func summary() -> String {
        var parts: [String] = []
        if ssid != cur.ssid { parts.append("SSID: \(cur.ssid) → \(ssid)") }
        if psk != cur.psk { parts.append("The password will change") }
        return parts.joined(separator: "\n") + "\n\nClients of this SSID are dropped and reconnect with the new settings."
    }
    private func note(_ t: String, _ c: Color) -> some View { Text(t).font(.caption).foregroundStyle(c) }
}
