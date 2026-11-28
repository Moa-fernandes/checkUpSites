import sys
from playwright.sync_api import sync_playwright

OVERLAP_JS = r"""
() => {
  const out = [];
  for (const el of document.querySelectorAll('body *')) {
    const hasText = Array.from(el.childNodes).some(n => n.nodeType === 3 && n.textContent.trim());
    if (!hasText) continue;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) continue;
    const x = r.left + r.width / 2;
    const y = r.top + Math.min(r.height / 2, 20);
    if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) continue;
    const top = document.elementFromPoint(x, y);
    const covered = !!top && top !== el && !el.contains(top);
    const topName = top
      ? top.tagName.toLowerCase() + (top.id ? '#' + top.id : '') +
        (typeof top.className === 'string' && top.className ? '.' + top.className.split(' ')[0] : '')
      : null;
    out.push({ text: el.textContent.trim().slice(0, 40), covered, top: topName });
  }
  return out;
}
"""

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://www.nivel3ti.com.br/"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900}, locale="pt-BR")
        page.goto(url, wait_until="load", timeout=30000)
        page.wait_for_timeout(3000)
        rows = page.evaluate(OVERLAP_JS)
        page.screenshot(path="topo.png", clip={"x": 0, "y": 0, "width": 1280, "height": 300})
        browser.close()

    covered = [r for r in rows if r["covered"]]
    print(f"Textos cobertos por outro elemento: {len(covered)} de {len(rows)}")
    for r in covered[:20]:
        print(f"- '{r['text']}' coberto por <{r['top']}>")
    print("Print do topo salvo em topo.png (na pasta do projeto)")

if __name__ == "__main__":
    main()