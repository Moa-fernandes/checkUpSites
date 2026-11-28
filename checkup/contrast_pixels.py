"""Contraste WCAG medido pelos pixels visíveis, com uma captura por tela."""

from __future__ import annotations

import base64
import time

LIST_JS = r"""
() => {
  const out = [];
  const sx = window.scrollX, sy = window.scrollY;
  for (const el of document.querySelectorAll('body *')) {
    const txt = Array.from(el.childNodes)
      .filter(n => n.nodeType === 3 && n.textContent.trim())
      .map(n => n.textContent.trim()).join(' ');
    if (!txt) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    if (el.closest('.sr-only')) continue;
    let eff = 1, anc = el;
    while (anc && anc.nodeType === 1) { eff *= parseFloat(getComputedStyle(anc).opacity); anc = anc.parentElement; }
    if (eff < 0.5) continue;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) continue;
    out.push({
      idx: out.length, text: txt.slice(0, 60), color: cs.color,
      size: parseFloat(cs.fontSize), weight: parseInt(cs.fontWeight, 10) || 400,
      pageX: r.left + sx, pageY: r.top + sy, w: r.width, h: r.height,
    });
    if (out.length >= 600) break;
  }
  return out;
}
"""

PIXEL_BATCH_JS = r"""
async ([b64, rects]) => {
  const toRgba = (str) => {
    const c = document.createElement('canvas');
    c.width = 1; c.height = 1;
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.fillStyle = 'rgb(1, 2, 3)';
    ctx.fillStyle = str;
    ctx.fillRect(0, 0, 1, 1);
    const d = ctx.getImageData(0, 0, 1, 1).data;
    if (d[0] === 1 && d[1] === 2 && d[2] === 3 && d[3] === 255) return null;
    return [d[0], d[1], d[2]];
  };
  const lumOf = (r, g, b) => {
    const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const img = new Image();
  img.src = 'data:image/png;base64,' + b64;
  await img.decode();
  const c = document.createElement('canvas');
  c.width = img.width; c.height = img.height;
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(img, 0, 0);
  const kx = img.width / innerWidth, ky = img.height / innerHeight;
  const out = [];
  for (const rc of rects) {
    const fg = toRgba(rc.color);
    if (!fg) { out.push({ idx: rc.idx, unknown: true }); continue; }
    const x = Math.max(0, Math.floor(rc.x * kx));
    const y = Math.max(0, Math.floor(rc.y * ky));
    const w = Math.min(Math.ceil(rc.w * kx), c.width - x);
    const h = Math.min(Math.ceil(rc.h * ky), c.height - y);
    if (w < 2 || h < 2) { out.push({ idx: rc.idx, unknown: true }); continue; }
    const d = ctx.getImageData(x, y, w, h).data;
    const lums = [];
    for (let i = 0; i < d.length; i += 16) lums.push(lumOf(d[i], d[i + 1], d[i + 2]));
    lums.sort((a, b) => a - b);
    const q = p => lums[Math.floor(p * (lums.length - 1))];
    const lf = lumOf(fg[0], fg[1], fg[2]);
    const lb = q(0.5);
    const ratio = (Math.max(lf, lb) + 0.05) / (Math.min(lf, lb) + 0.05);
    out.push({ idx: rc.idx, ratio, spread: q(0.9) - q(0.1) });
  }
  return out;
}
"""


HIDE_OVERLAYS_JS = r"""
() => {
  let count = 0;
  const area = innerWidth * innerHeight;
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.position !== 'fixed' || cs.display === 'none') continue;
    if (parseFloat(cs.opacity) < 0.5) continue;
    const r = el.getBoundingClientRect();
    if (r.width * r.height < area * 0.5) continue;
    el.style.setProperty('display', 'none', 'important');
    count++;
  }
  return count;
}
"""


def _needed(size: float, weight: int) -> float:
    large = size >= 24 or (size >= 18.66 and weight >= 700)
    return 3.0 if large else 4.5


def measure_contrast_pixels(page, vw: int = 1280, vh: int = 900, max_seconds: float = 12.0) -> list[dict]:
    """Mede o contraste de cada texto visível. Status: ok, FALHA, verificar ou não medido."""
    started = time.monotonic()
    page.evaluate(HIDE_OVERLAYS_JS)
    items = page.evaluate(LIST_JS)
    if not items:
        return []
    page.add_style_tag(content="body *{color:transparent !important;text-shadow:none !important;}")

    by_tile: dict[int, list] = {}
    for it in items:
        tile = int((it["pageY"] + it["h"] / 2) // vh)
        by_tile.setdefault(tile, []).append(it)

    out: list[dict] = []
    for tile in sorted(by_tile):
        if time.monotonic() - started > max_seconds:
            break
        page.evaluate("y => window.scrollTo({ top: y, behavior: 'instant' })", tile * vh)
        page.wait_for_timeout(150)
        scroll_x, scroll_y = page.evaluate("() => [window.scrollX, window.scrollY]")
        png = page.screenshot(full_page=False)
        rects = [
            {"idx": it["idx"], "x": it["pageX"] - scroll_x, "y": it["pageY"] - scroll_y,
             "w": it["w"], "h": it["h"], "color": it["color"]}
            for it in by_tile[tile]
        ]
        res = {r["idx"]: r for r in page.evaluate(PIXEL_BATCH_JS, [base64.b64encode(png).decode(), rects])}
        for it in by_tile[tile]:
            r = res.get(it["idx"], {})
            need = _needed(it["size"], it["weight"])
            if "ratio" not in r:
                status, ratio = "não medido", None
            else:
                ratio = round(r["ratio"], 2)
                if r["spread"] > 0.08:
                    status = "verificar"
                elif ratio < need:
                    status = "FALHA"
                else:
                    status = "ok"
            out.append({
                "status": status, "ratio": ratio, "needed": need,
                "fontSize": it["size"], "fontWeight": it["weight"],
                "text": it["text"], "color": it["color"],
            })
    return out