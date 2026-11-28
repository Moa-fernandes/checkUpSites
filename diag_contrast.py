import sys
from playwright.sync_api import sync_playwright

CONTRAST_JS = r"""
() => {
  const parse = (c) => {
    const m = c && c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(',').map(s => parseFloat(s));
    return { r: p[0], g: p[1], b: p[2], a: p.length === 4 ? p[3] : 1 };
  };
  const lum = (c) => {
    const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };
  const rows = [];
  for (const el of document.querySelectorAll('body *')) {
    const text = Array.from(el.childNodes)
      .filter(n => n.nodeType === 3 && n.textContent.trim())
      .map(n => n.textContent.trim()).join(' ');
    if (!text) continue;
    const cs = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height || cs.visibility === 'hidden' || cs.display === 'none') continue;
    const fg = parse(cs.color);
    if (!fg) continue;
    let opacity = 1, bgImage = false, opaque = null, node = el;
    while (node && node.nodeType === 1) {
      const s = getComputedStyle(node);
      opacity *= parseFloat(s.opacity);
      if (s.backgroundImage && s.backgroundImage !== 'none') bgImage = true;
      const bg = parse(s.backgroundColor);
      if (bg && bg.a >= 1) { opaque = bg; break; }
      node = node.parentElement;
    }
    const bg = opaque || { r: 255, g: 255, b: 255, a: 1 };
    const l1 = lum(fg), l2 = lum(bg);
    const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    rows.push({
      ratio: Math.round(ratio * 100) / 100,
      text: text.slice(0, 50),
      fg: cs.color,
      bg: opaque ? `rgb(${bg.r},${bg.g},${bg.b})` : "PADRÃO BRANCO (fundo não resolvido)",
      opacity: Math.round(opacity * 100) / 100,
      bgImage,
      resolved: !!opaque,
    });
  }
  return rows;
}
"""

INPUTS_JS = r"""
() => Array.from(document.querySelectorAll(
  'input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset]):not([type=image]), select, textarea'
)).map(el => ({
  tag: el.tagName.toLowerCase(),
  type: el.type,
  visible: el.getClientRects().length > 0,
  labels: el.labels ? el.labels.length : 0,
  aria: !!(el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || el.getAttribute('title')),
  inLabel: !!el.closest('label'),
  html: el.outerHTML.slice(0, 140),
}))
"""

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://www.nivel3ti.com.br/"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900}, locale="pt-BR")
        page.goto(url, wait_until="load", timeout=30000)
        page.wait_for_timeout(3000)
        rows = page.evaluate(CONTRAST_JS)
        inputs = page.evaluate(INPUTS_JS)
        browser.close()

    failing = [r for r in rows if r["ratio"] < 4.5]
    print(f"\n=== CONTRASTE ({url}) ===")
    print(f"Textos analisados: {len(rows)} | abaixo de 4.5:1: {len(failing)}")
    print(f"  sem fundo opaco resolvido (usou branco): {sum(not r['resolved'] for r in failing)}")
    print(f"  com background-image no caminho:          {sum(r['bgImage'] for r in failing)}")
    print(f"  com opacidade < 1 no caminho:             {sum(r['opacity'] < 1 for r in failing)}")
    for r in failing[:15]:
        print(f"- {r['ratio']}:1 | '{r['text']}' | texto {r['fg']} | fundo {r['bg']} | opac {r['opacity']} | img {r['bgImage']}")

    unlabeled = [i for i in inputs if i["labels"] == 0 and not i["aria"] and not i["inLabel"]]
    print(f"\n=== CAMPOS SEM RÓTULO ===")
    print(f"Campos encontrados: {len(inputs)} | sem rótulo: {len(unlabeled)} | sem rótulo e visíveis: {sum(i['visible'] for i in unlabeled)}")
    for i in unlabeled:
        print(f"- visível={i['visible']} | {i['html']}")

if __name__ == "__main__":
    main()