import sys
import time
import base64
from playwright.sync_api import sync_playwright

LIST_JS = r"""
() => {
  const out = [];
  for (const el of document.querySelectorAll('body *')) {
    const txt = Array.from(el.childNodes)
      .filter(n => n.nodeType === 3 && n.textContent.trim())
      .map(n => n.textContent.trim()).join(' ');
    if (!txt) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    const idx = out.length;
    el.setAttribute('data-diag', String(idx));
    out.push({
      idx, text: txt.slice(0, 50), color: cs.color,
      size: parseFloat(cs.fontSize), weight: parseInt(cs.fontWeight, 10) || 400,
    });
    if (out.length >= 400) break;
  }
  return out;
}
"""

RECT_JS = r"""
(i) => {
  const e = document.querySelector(`[data-diag='${i}']`);
  if (!e) return null;
  e.scrollIntoView({ block: 'center', inline: 'nearest' });
  const r = e.getBoundingClientRect();
  return { x: r.left, y: r.top, w: r.width, h: r.height, vw: innerWidth, vh: innerHeight };
}
"""

PIXEL_JS = r"""
async ([b64, colorStr]) => {
  const toRgba = (str) => {
    const c = document.createElement('canvas');
    c.width = 1; c.height = 1;
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.fillStyle = 'rgb(1, 2, 3)';
    ctx.fillStyle = str;
    ctx.fillRect(0, 0, 1, 1);
    const d = ctx.getImageData(0, 0, 1, 1).data;
    if (d[0] === 1 && d[1] === 2 && d[2] === 3 && d[3] === 255) return null;
    return [d[0], d[1], d[2], d[3] / 255];
  };
  const fg = toRgba(colorStr);
  if (!fg) return { unknown: true };
  const img = new Image();
  img.src = 'data:image/png;base64,' + b64;
  await img.decode();
  const c = document.createElement('canvas');
  c.width = img.width; c.height = img.height;
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(img, 0, 0);
  const d = ctx.getImageData(0, 0, c.width, c.height).data;
  const lumOf = (r, g, b) => {
    const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const lums = [];
  for (let i = 0; i < d.length; i += 4) lums.push(lumOf(d[i], d[i + 1], d[i + 2]));
  if (!lums.length) return { unknown: true };
  lums.sort((a, b) => a - b);
  const q = p => lums[Math.floor(p * (lums.length - 1))];
  const bgLum = q(0.5);
  const lf = lumOf(fg[0], fg[1], fg[2]);
  const ratio = (Math.max(lf, bgLum) + 0.05) / (Math.min(lf, bgLum) + 0.05);
  return { ratio: Math.round(ratio * 100) / 100, spread: q(0.9) - q(0.1) };
}
"""

def needed(size, weight):
    large = size >= 24 or (size >= 18.66 and weight >= 700)
    return 3.0 if large else 4.5

def set_hidden(page, idx, flag):
    page.evaluate(
        "([i, f]) => { const e = document.querySelector(`[data-diag='${i}']`);"
        " if (e) e.classList.toggle('__diag_hide', f); }",
        [idx, flag],
    )

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://www.nivel3ti.com.br/"
    started = time.monotonic()
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900}, locale="pt-BR")
        page.goto(url, wait_until="load", timeout=30000)
        page.wait_for_timeout(3000)
        page.add_style_tag(content=".__diag_hide{color:transparent !important;text-shadow:none !important;}")
        items = page.evaluate(LIST_JS)
        for it in items:
            rect = page.evaluate(RECT_JS, it["idx"])
            if not rect:
                continue
            x = max(0, rect["x"]); y = max(0, rect["y"])
            w = min(rect["w"], rect["vw"] - x); h = min(rect["h"], rect["vh"] - y)
            if w < 4 or h < 4:
                continue
            page.wait_for_timeout(80)
            set_hidden(page, it["idx"], True)
            png = page.screenshot(clip={"x": x, "y": y, "width": w, "height": h})
            set_hidden(page, it["idx"], False)
            stats = page.evaluate(PIXEL_JS, [base64.b64encode(png).decode(), it["color"]])
            if stats.get("unknown"):
                results.append(("não medido", None, None, None, it["text"], it["color"]))
                continue
            need = needed(it["size"], it["weight"])
            if stats["spread"] > 0.08:
                status = "verificar"
            elif stats["ratio"] < need:
                status = "FALHA"
            else:
                status = "ok"
            results.append((status, stats["ratio"], need, round(stats["spread"], 3), it["text"], it["color"]))
        browser.close()

    elapsed = time.monotonic() - started
    statuses = ("FALHA", "verificar", "ok", "não medido")
    counts = {s: sum(1 for r in results if r[0] == s) for s in statuses}
    print(f"\n=== CONTRASTE POR PIXELS, PÁGINA INTEIRA ({url}) ===")
    print(f"Textos: {len(results)} | FALHA: {counts['FALHA']} | verificar: {counts['verificar']} | ok: {counts['ok']} | não medido: {counts['não medido']}")
    print(f"Tempo de medição: {elapsed:.1f}s")

    print("\nFALHAS confirmadas:")
    for status, ratio, need, spread, text, color in results:
        if status == "FALHA":
            print(f"- {ratio}:1 (mín. {need}) | '{text}' | texto {color}")

    print("\nVERIFICAR (fundo heterogêneo, não é falha):")
    for status, ratio, need, spread, text, color in results:
        if status == "verificar":
            print(f"- {ratio}:1 | dispersão {spread} | '{text}'")

if __name__ == "__main__":
    main()