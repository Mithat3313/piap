#!/usr/bin/env swift
// Draws PiAP Manager's app icon and writes Resources/AppIcon.icns.
//   cd macos && ./make-icon.swift
// Kept as code rather than a binary blob so the icon can be adjusted and regenerated: it is drawn
// with CoreGraphics at every size iconutil wants, so the small sizes stay legible instead of being
// a blurry downscale of the large one.
//
// The mark: a shield (this is about protecting what the clients send) with Wi-Fi arcs inside it, on
// the same dark blue the panels use. At 16 pt only the silhouette survives, which is why the shield
// is wide and the arcs are few and thick.

import AppKit

let bgTop    = NSColor(srgbRed: 0.106, green: 0.153, blue: 0.259, alpha: 1)  // #1b2742
let bgBottom = NSColor(srgbRed: 0.043, green: 0.063, blue: 0.118, alpha: 1)  // #0b101e
let accent   = NSColor(srgbRed: 0.310, green: 0.549, blue: 1.000, alpha: 1)  // #4f8cff
let ink      = NSColor.white

func shieldPath(in r: CGRect) -> NSBezierPath {
    // A shield: straight shoulders, sides curving into a point at the bottom.
    let w = r.width, h = r.height, x = r.minX, y = r.minY
    let p = NSBezierPath()
    p.move(to: CGPoint(x: x + w * 0.5, y: y + h))                      // top centre
    p.line(to: CGPoint(x: x + w, y: y + h * 0.78))                     // right shoulder
    p.curve(to: CGPoint(x: x + w * 0.5, y: y),                         // down to the tip
            controlPoint1: CGPoint(x: x + w, y: y + h * 0.30),
            controlPoint2: CGPoint(x: x + w * 0.80, y: y + h * 0.10))
    p.curve(to: CGPoint(x: x, y: y + h * 0.78),                        // and back up the left side
            controlPoint1: CGPoint(x: x + w * 0.20, y: y + h * 0.10),
            controlPoint2: CGPoint(x: x, y: y + h * 0.30))
    p.close()
    return p
}

func draw(size s: CGFloat) -> NSImage {
    let img = NSImage(size: NSSize(width: s, height: s))
    img.lockFocus()
    let ctx = NSGraphicsContext.current!.cgContext
    ctx.setShouldAntialias(true)

    // rounded-square background with the system's corner proportion
    let bg = NSBezierPath(roundedRect: NSRect(x: 0, y: 0, width: s, height: s),
                          xRadius: s * 0.2237, yRadius: s * 0.2237)
    bg.addClip()
    NSGradient(starting: bgTop, ending: bgBottom)!.draw(in: NSRect(x: 0, y: 0, width: s, height: s), angle: -90)

    // the shield, filled just lighter than the background and outlined in the accent
    let inset = s * 0.17
    let rect = NSRect(x: inset, y: inset * 0.85, width: s - inset * 2, height: s - inset * 1.7)
    let shield = shieldPath(in: rect)
    NSColor(srgbRed: 0.176, green: 0.251, blue: 0.408, alpha: 1).setFill()
    shield.fill()
    accent.setStroke()
    shield.lineWidth = max(1, s * 0.035)
    shield.stroke()

    // Wi-Fi arcs, clipped to the shield so nothing spills past its edge
    NSGraphicsContext.saveGraphicsState()
    shield.addClip()
    let cx = rect.midX, cy = rect.minY + rect.height * 0.30
    let lw = max(1, s * 0.058)
    for (i, f) in [0.34, 0.52, 0.70].enumerated() {
        let a = NSBezierPath()
        a.appendArc(withCenter: CGPoint(x: cx, y: cy), radius: rect.width * CGFloat(f),
                    startAngle: 35, endAngle: 145)
        a.lineWidth = lw * [1.0, 0.92, 0.84][i]
        a.lineCapStyle = .round
        ink.withAlphaComponent([1.0, 0.8, 0.55][i]).setStroke()
        a.stroke()
    }
    // the transmitter dot
    accent.setFill()
    NSBezierPath(ovalIn: NSRect(x: cx - lw * 0.68, y: cy - lw * 0.68, width: lw * 1.36, height: lw * 1.36)).fill()
    NSGraphicsContext.restoreGraphicsState()

    img.unlockFocus()
    return img
}

func png(_ image: NSImage, _ px: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px,
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: px, height: px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    draw(size: CGFloat(px)).draw(in: NSRect(x: 0, y: 0, width: px, height: px))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let here = URL(fileURLWithPath: CommandLine.arguments.first.map { ($0 as NSString).deletingLastPathComponent } ?? ".")
let iconset = here.appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try! FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

for (px, name) in [(16, "icon_16x16"), (32, "icon_16x16@2x"), (32, "icon_32x32"), (64, "icon_32x32@2x"),
                   (128, "icon_128x128"), (256, "icon_128x128@2x"), (256, "icon_256x256"),
                   (512, "icon_256x256@2x"), (512, "icon_512x512"), (1024, "icon_512x512@2x")] {
    try! png(NSImage(), px).write(to: iconset.appendingPathComponent("\(name).png"))
}

let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", iconset.path, "-o", here.appendingPathComponent("Resources/AppIcon.icns").path]
try! p.run(); p.waitUntilExit()
try? FileManager.default.removeItem(at: iconset)
print(p.terminationStatus == 0 ? "OK: Resources/AppIcon.icns" : "iconutil failed (\(p.terminationStatus))")
exit(p.terminationStatus)
