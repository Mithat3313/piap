import SwiftUI

// MARK: - Yayınlar (ana ekran): her slot = bir radyo + bir tünel
struct SlotsView: View {
    @EnvironmentObject var app: AppState
    @State private var confirmReboot = false
    @State private var pendingActivate: (slot: String, profile: String, stealFrom: String?)? = nil
    @State private var pendingSwap: (a: String, b: String)? = nil
    @State private var pendingToggle: (slot: String, on: Bool)? = nil
    @State private var pendingPin: String? = nil
    @State private var typed = ""          // yazılı onay (Pi tarafında da zorunlu; yanlış tıklamaya karşı)
    var s: Status { app.status }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if s.slots.isEmpty { ProgressView("Durum alınıyor…").frame(maxWidth: .infinity, minHeight: 120) }
                ForEach(s.slots) { slot in slotCard(slot) }
                globalCard
                HStack {
                    Button("Yenile") { Task { await app.refreshAll() } }
                    Toggle("Otomatik (5 sn)", isOn: $app.autoRefresh).toggleStyle(.checkbox)
                    Button("Tam doğrulama") { app.verify() }
                    Button("Firewall'ı yeniden uygula") { app.firewall() }
                    Spacer()
                    Button("Yeniden başlat", role: .destructive) { confirmReboot = true }
                }
                if let v = app.verifyResult {
                    GroupBox("Son doğrulama / aktivasyon") { Text(v).font(.system(.caption, design: .monospaced)).frame(maxWidth: .infinity, alignment: .leading) }
                }
                Text("Son güncelleme: \(s.ts.formatted(date: .omitted, time: .standard))").font(.caption2).foregroundStyle(.secondary)
            }
            .padding()
        }
        .navigationTitle("Yayınlar")
        .confirmationDialog("Pi yeniden başlatılsın mı?", isPresented: $confirmReboot) {
            Button("Yeniden başlat", role: .destructive) { app.reboot() }
        } message: { Text("Tüm yayınlar, tüneller ve Pi'deki diğer servisler ~1-2 dakika kapalı kalır. Bluetooth bağlantısı kopar.") }
        // ATAMA SABİTLEME: eşlemeyi değiştiren her işlem, etkilenen yayınların SSID'sinin AYNEN yazılmasını ister.
        .alert("\(pendingActivate?.slot ?? "") yayını \(pendingActivate?.profile ?? "") profiline geçsin mi?",
               isPresented: Binding(get: { pendingActivate != nil }, set: { if !$0 { pendingActivate = nil; typed = "" } })) {
            TextField(activateExpected, text: $typed)
            Button(pendingActivate?.stealFrom != nil ? "Al ve geç" : "Geç") {
                if let p = pendingActivate { app.activateProfile(p.profile, slot: p.slot, force: p.stealFrom != nil, confirm: typed.trimmingCharacters(in: .whitespaces)) }
                pendingActivate = nil; typed = ""
            }.disabled(typed.trimmingCharacters(in: .whitespaces) != activateExpected)
            Button("Vazgeç", role: .cancel) { pendingActivate = nil; typed = "" }
        } message: {
            if let from = pendingActivate?.stealFrom {
                Text("⚠️ \(pendingActivate?.profile ?? "") şu an \(from) yayınında. Oradan alınır: \(from) yayını siz yeni bir profil atayana kadar TÜNELSİZ kalır (killswitch tutar). Bu yayının tüneli yeniden kurulur.\n\nBu işlem yayın–VPN eşlemesini değiştirir. Onaylamak için aynen yazın:\n\(activateExpected)")
            } else {
                Text("Bu yayının tüneli yeniden kurulur; istemcileri birkaç saniye internetsiz kalır (sızıntı olmaz). Handshake gelmezse eski profile dönülür.\n\nBu işlem yayın–VPN eşlemesini değiştirir. Onaylamak için aynen yazın:\n\(activateExpected)")
            }
        }
        .alert("\(pendingSwap?.a ?? "") ⇄ \(pendingSwap?.b ?? "") tünelleri takas edilsin mi?",
               isPresented: Binding(get: { pendingSwap != nil }, set: { if !$0 { pendingSwap = nil; typed = "" } })) {
            TextField(swapExpected, text: $typed)
            Button("Takas et") { if let sw = pendingSwap { app.swapSlots(sw.a, sw.b, confirm: typed.trimmingCharacters(in: .whitespaces)) }; pendingSwap = nil; typed = "" }
                .disabled(typed.trimmingCharacters(in: .whitespaces) != swapExpected)
            Button("Vazgeç", role: .cancel) { pendingSwap = nil; typed = "" }
        } message: {
            if let sw = pendingSwap {
                Text("\(app.ssid(of: sw.a)) → \(s.slots.first { $0.name == sw.b }?.vpn.profile ?? "—")\n\(app.ssid(of: sw.b)) → \(s.slots.first { $0.name == sw.a }?.vpn.profile ?? "—")\nİki yayının istemcileri de kısa süre internetsiz kalır. 1-3 dakika sürebilir.\n\nBu işlem yayın–VPN eşlemesini değiştirir. Onaylamak için aynen yazın:\n\(swapExpected)")
            }
        }
        .alert("\(pendingPin ?? "") yeniden sabitlensin mi?",
               isPresented: Binding(get: { pendingPin != nil }, set: { if !$0 { pendingPin = nil; typed = "" } })) {
            TextField(pinExpected, text: $typed)
            Button("Sabitle ve yayını başlat") { if let p = pendingPin { app.pinSlot(p, confirm: typed.trimmingCharacters(in: .whitespaces)) }; pendingPin = nil; typed = "" }
                .disabled(typed.trimmingCharacters(in: .whitespaces) != pinExpected)
            Button("Vazgeç", role: .cancel) { pendingPin = nil; typed = "" }
        } message: {
            if let p = pendingPin {
                Text("Yayının MEVCUT durumu (SSID, profil, sunucu anahtarı, radyo MAC) sabit olarak kaydedilir.\nŞu an: \(app.ssid(of: p)) → \(s.slots.first { $0.name == p }?.vpn.profile ?? "—")\nBu değişikliği siz yapmadıysanız önce araştırın.\n\nOnaylamak için aynen yazın:\n\(pinExpected)")
            }
        }
        .confirmationDialog("\(pendingToggle?.slot ?? "") yayını \(pendingToggle?.on == true ? "açılsın" : "kapatılsın") mı?",
                            isPresented: Binding(get: { pendingToggle != nil }, set: { if !$0 { pendingToggle = nil } })) {
            Button(pendingToggle?.on == true ? "Aç" : "Kapat", role: pendingToggle?.on == true ? nil : .destructive) {
                if let t = pendingToggle { app.setSlotEnabled(t.slot, t.on) }; pendingToggle = nil
            }
        } message: { Text(pendingToggle?.on == true ? "SSID yayına girer, tünel kurulur." : "SSID kapanır, bağlı istemciler düşer, tünel kapatılır. Diğer yayın etkilenmez.") }
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
                // radyo
                VStack(alignment: .leading, spacing: 5) {
                    Label("Wi-Fi", systemImage: "wifi").font(.caption).foregroundStyle(.secondary)
                    Text(slot.ap.ssid).font(.title3).bold()
                    Text("\(slot.ap.band) · kanal \(slot.ap.channel) · \(slot.ap.width) MHz · \(slot.ap.iface)").font(.caption).monospaced().foregroundStyle(.secondary)
                    HStack(spacing: 6) {
                        Circle().fill(slot.ap.up ? .green : .red).frame(width: 8, height: 8)
                        Text(slot.ap.up ? "yayında" : "KAPALI").font(.callout)
                        Text("· \(slot.clients) istemci · \(slot.net)").font(.callout).foregroundStyle(.secondary)
                    }
                }
                .frame(minWidth: 220, alignment: .leading)
                Divider()
                // tünel
                VStack(alignment: .leading, spacing: 5) {
                    Label("VPN çıkışı", systemImage: "lock.shield").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Menu {
                            ForEach(app.profiles) { p in
                                Button {
                                    if p.slot != slot.name { pendingActivate = (slot.name, p.name, p.slot) }
                                } label: {
                                    HStack { Text(p.name); if let s = p.slot { Text(s == slot.name ? "(bu yayın)" : "— \(s)'den alınır") } }
                                }.disabled(p.slot == slot.name)
                            }
                            if s.slots.count == 2, let other = s.slots.first(where: { $0.name != slot.name }) {
                                Divider()
                                Button("⇄ \(other.name) ile takas et") { pendingSwap = (slot.name, other.name) }
                            }
                        } label: {
                            Text(slot.vpn.profile ?? "profil seç").bold()
                        }
                        .menuStyle(.borderlessButton).fixedSize()
                        .disabled(app.busy != nil || !slot.enabled)
                        Circle().fill(slot.vpn.healthy ? .green : .red).frame(width: 8, height: 8)
                        Text(slot.vpn.healthy ? "handshake \(fmtDur(slot.vpn.handshakeAge ?? 0)) önce" : "tünel yok").font(.caption).foregroundStyle(.secondary)
                    }
                    Text("\(slot.vpn.endpoint) · \(slot.vpn.iface) \(slot.vpn.address)").font(.caption).monospaced().foregroundStyle(.secondary)
                    Text("↓\(fmtBytes(slot.vpn.rx)) ↑\(fmtBytes(slot.vpn.tx))").font(.caption).foregroundStyle(.secondary)
                    HStack(spacing: 8) {
                        Text("Çıkış IP:").font(.callout).foregroundStyle(.secondary)
                        Text(app.exitIP[slot.name] ?? "—").font(.callout).monospaced().bold()
                        Button("Sorgula") { app.fetchExitIP(slot.name) }.controlSize(.small).disabled(app.busy != nil || !slot.vpn.up)
                    }
                }
                .frame(minWidth: 260, alignment: .leading)
                Spacer()
                VStack(alignment: .trailing, spacing: 8) {
                    Toggle("Yayın", isOn: Binding(get: { slot.enabled }, set: { pendingToggle = (slot.name, $0) }))
                        .toggleStyle(.switch).controlSize(.small).disabled(app.busy != nil)
                    HStack(spacing: 4) {
                        Image(systemName: slot.killswitch ? "checkmark.shield.fill" : "xmark.shield.fill").foregroundStyle(slot.killswitch ? .green : .red)
                        Text("killswitch").font(.caption2)
                    }
                    HStack(spacing: 4) {
                        Image(systemName: slot.pin.ok ? (slot.pin.pinned ? "lock.fill" : "lock.open") : "exclamationmark.lock.fill").foregroundStyle(slot.pin.ok ? (slot.pin.pinned ? .green : .orange) : .red)
                        Text(slot.pin.ok ? (slot.pin.pinned ? "sabit: \(slot.pin.profile ?? "")" : "sabit yok") : "SABİT İHLALİ").font(.caption2)
                    }.help(slot.pin.msg)
                }
            }
            if !slot.pin.ok {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("ATAMA İHLALİ — yayın durduruldu (fail-closed).").bold().foregroundStyle(.red)
                        Text(slot.pin.violation ?? slot.pin.msg).font(.caption).monospaced()
                        Text("Bu değişikliği siz yapmadıysanız önce araştırın. Mevcut durum doğruysa yeniden sabitleyin.").font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Yeniden sabitle") { pendingPin = slot.name }.controlSize(.small).disabled(app.busy != nil)
                }
                .padding(8).background(Color.red.opacity(0.08)).clipShape(RoundedRectangle(cornerRadius: 6))
            }
          }
        } label: {
            HStack { Circle().fill(healthy ? .green : (slot.enabled ? .orange : .gray)).frame(width: 10, height: 10); Text(slot.name).bold().monospaced()
                     Text(healthy ? "sağlıklı" : (slot.enabled ? "sorun var" : "kapalı")).font(.caption).foregroundStyle(.secondary) }
        }
    }

    var globalCard: some View {
        GroupBox {
            HStack(spacing: 24) {
                row("LAN", "\(s.lan.iface) \(s.lan.ip)"); row("Gateway", s.lan.gw)
                row("Çalışma", fmtDur(s.uptime)); row("Yük", String(format: "%.2f", s.load))
                row("Sıcaklık", s.temp.map { String(format: "%.1f°C", $0) } ?? "-")
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

// MARK: - İstemciler
struct ClientsView: View {
    @EnvironmentObject var app: AppState
    var body: some View {
        VStack(alignment: .leading) {
            if app.clients.isEmpty {
                ContentUnavailableView("Bağlı istemci yok", systemImage: "iphone.slash", description: Text("Yayınlara bağlanan cihazlar burada görünür."))
            } else {
                Table(app.clients) {
                    TableColumn("Yayın") { c in Text(c.slot).monospaced() }.width(50)
                    TableColumn("Cihaz") { c in Text(c.hostname ?? "—") }
                    TableColumn("IP") { c in Text(c.ip ?? "—").monospaced() }
                    TableColumn("MAC") { c in Text(c.mac).monospaced().font(.caption) }
                    TableColumn("Sinyal") { c in Text(c.signal.map { "\($0) dBm" } ?? "—").foregroundStyle((c.signal ?? -100) > -65 ? .green : .orange) }
                    TableColumn("Hız") { c in Text(c.txRate.map { String(format: "%.0f Mbps", $0) } ?? "—") }
                    TableColumn("Süre") { c in Text(c.connected.map(fmtDur) ?? "—") }
                    TableColumn("Trafik") { c in Text("↓\(fmtBytes(c.tx)) ↑\(fmtBytes(c.rx))").font(.caption) }
                    TableColumn("") { c in Button("Düşür") { app.kick(c) }.controlSize(.small) }.width(60)
                }
            }
            HStack { Button("Yenile") { Task { await app.refreshClients() } }; Text("\(app.clients.count) istemci").foregroundStyle(.secondary) }.padding()
        }
        .navigationTitle("İstemciler")
        .task { await app.refreshClients() }
    }
}

// MARK: - Wi-Fi (slot başına)
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
                Picker("Yayın", selection: $slot) {
                    ForEach(app.status.slots) { s in Text("\(s.name) — \(s.ap.ssid) (\(s.ap.band))").tag(s.name) }
                }.pickerStyle(.segmented)
            }
            SwiftUI.Section {
                TextField("Ağ adı (SSID)", text: $ssid).textFieldStyle(.roundedBorder)
                if !ssidValid && !ssid.isEmpty { note("SSID 1-32 bayt olmalı (şu an \(ssid.utf8.count)).", .red) }
                else if ssidValid && !ssid.hasSuffix("_nomap") { note("`_nomap` ile bitmesi önerilir: telefonlar bu AP'yi Google/Apple konum veritabanına bildirmez.", .orange) }
                HStack {
                    Group { if showPsk { TextField("Parola", text: $psk) } else { SecureField("Parola", text: $psk) } }
                        .textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced))
                    Button { showPsk.toggle() } label: { Image(systemName: showPsk ? "eye.slash" : "eye") }.help(showPsk ? "Gizle" : "Göster")
                    Button {
                        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(psk, forType: .string)
                        copied = true; DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: { Image(systemName: copied ? "checkmark" : "doc.on.doc") }.help("Parolayı kopyala").disabled(psk.isEmpty)
                }
                if !pskValid && !psk.isEmpty { note("Parola 8-63 karakter, yalnızca yazdırılabilir ASCII olmalı (şu an \(psk.count)).", .red) }
            } header: { Text("Misafir ağı — \(slot)") } footer: {
                Text("Değişiklik uygulanınca yalnızca bu yayının hostapd'si yeniden başlar; ona bağlı istemciler düşer. Diğer yayın ve Bluetooth etkilenmez.")
            }
            SwiftUI.Section("Radyo") {
                LabeledContent("Arayüz", value: cur.iface.isEmpty ? "—" : cur.iface)
                LabeledContent("Bant / kanal", value: cur.band.isEmpty ? "—" : "\(cur.band) · kanal \(cur.channel)")
                LabeledContent("VPN çıkışı", value: app.status.slots.first { $0.name == slot }?.vpn.profile ?? "—")
            }
            SwiftUI.Section {
                HStack {
                    Button("Uygula") { confirm = true }.keyboardShortcut(.defaultAction)
                        .disabled(!changed || !ssidValid || !pskValid || app.busy != nil || !cur.loaded)
                    Button("Vazgeç") { load() }.disabled(!changed)
                    Spacer()
                    if app.busy != nil { ProgressView().controlSize(.small) }
                    else if changed { Text("Kaydedilmemiş değişiklik").font(.caption).foregroundStyle(.orange) }
                    else if cur.loaded { Text("Güncel").font(.caption).foregroundStyle(.secondary) }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Wi-Fi")
        .task { if slot.isEmpty { slot = app.slotNames.first ?? "" }; await app.refreshWifi(slot); load() }
        .onChange(of: slot) { _, s in Task { await app.refreshWifi(s); load() } }
        .onChange(of: cur.loaded) { _, _ in if !changed { load() } }
        .confirmationDialog("\(slot) Wi-Fi ayarları değiştirilsin mi?", isPresented: $confirm) {
            Button("Uygula") { app.setWifi(slot: slot, ssid: ssid, psk: psk) }
        } message: { Text(summary()) }
    }
    private func load() { ssid = cur.ssid; psk = cur.psk }
    private func summary() -> String {
        var parts: [String] = []
        if ssid != cur.ssid { parts.append("SSID: \(cur.ssid) → \(ssid)") }
        if psk != cur.psk { parts.append("Parola değişecek") }
        return parts.joined(separator: "\n") + "\n\nBu yayına bağlı istemciler düşer ve yeni bilgilerle tekrar bağlanır."
    }
    private func note(_ t: String, _ c: Color) -> some View { Text(t).font(.caption).foregroundStyle(c) }
}
