(function () {
  // CRC16-CCITT (0x1021, init 0xFFFF) para Pix BR Code EMV
  function crc16(str) {
    let crc = 0xFFFF;
    for (let i = 0; i < str.length; i++) {
      crc ^= str.charCodeAt(i) << 8;
      for (let j = 0; j < 8; j++) {
        if (crc & 0x8000) crc = ((crc << 1) ^ 0x1021) & 0xFFFF;
        else crc = (crc << 1) & 0xFFFF;
      }
    }
    return crc.toString(16).toUpperCase().padStart(4, '0');
  }

  function emv(id, val) {
    const s = String(val);
    return `${id}${String(s.length).padStart(2, '0')}${s}`;
  }

  window.buildPixPayload = function (pixKey, amountStr, merchantName, merchantCity) {
    const key = (pixKey || 'moacirsistemax@gmail.com').trim();
    const gui = emv('00', 'br.gov.bcb.pix');
    const chave = emv('01', key);
    const mai = emv('26', gui + chave);
    const amt = amountStr && String(amountStr).trim() !== ''
      ? emv('54', Number(String(amountStr).replace(',', '.')).toFixed(2))
      : '';
    const name = (merchantName || 'CHECKUP').toUpperCase().slice(0, 25);
    const city = (merchantCity || 'RIO DE JANEIRO').toUpperCase().slice(0, 15);
    const body =
      emv('00', '01') +
      mai +
      emv('52', '0000') +
      emv('53', '986') +
      amt +
      emv('58', 'BR') +
      emv('59', name) +
      emv('60', city) +
      '6304';
    return body + crc16(body);
  };

  // Gerador QR Code Versão 3 (29x29) modo Byte, nível L com Reed-Solomon em GF(256)
  const SIZE = 29;
  const EXP = new Uint8Array(256);
  const LOG = new Uint8Array(256);
  (function initGF() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11D;
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return EXP[LOG[a] + LOG[b]];
  }

  function rsGeneratorPoly(ecLen) {
    let poly = [1];
    for (let i = 0; i < ecLen; i++) {
      const next = new Array(poly.length + 1).fill(0);
      const factor = EXP[i];
      for (let j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= gfMul(poly[j], factor);
      }
      poly = next;
    }
    return poly.slice(1);
  }

  function rsEncode(dataBytes, ecLen) {
    const gen = rsGeneratorPoly(ecLen);
    const rem = new Array(ecLen).fill(0);
    for (let i = 0; i < dataBytes.length; i++) {
      const factor = dataBytes[i] ^ rem[0];
      rem.shift();
      rem.push(0);
      for (let j = 0; j < ecLen; j++) {
        rem[j] ^= gfMul(gen[j], factor);
      }
    }
    return rem;
  }

  function buildQrMatrix(text) {
    const utf8 = new TextEncoder().encode(text);
    const totalDataCodewords = 55; // v3-L total 70 codewords, EC 15 -> 55 data codewords
    const bits = [];
    function pushBits(val, len) {
      for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
    }

    pushBits(0b0100, 4); // Byte mode
    pushBits(utf8.length, 8); // v3 character count (8 bits)
    for (let i = 0; i < utf8.length; i++) pushBits(utf8[i], 8);

    const maxBits = totalDataCodewords * 8;
    const termLen = Math.min(4, Math.max(0, maxBits - bits.length));
    pushBits(0, termLen);
    while (bits.length % 8 !== 0) bits.push(0);

    const dataCodewords = [];
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
      dataCodewords.push(b);
    }
    const pads = [0xEC, 0x11];
    let padIdx = 0;
    while (dataCodewords.length < totalDataCodewords) {
      dataCodewords.push(pads[padIdx % 2]);
      padIdx++;
    }

    const ecCodewords = rsEncode(dataCodewords, 15);
    const finalBytes = dataCodewords.concat(ecCodewords);

    const grid = Array.from({ length: SIZE }, () => new Array(SIZE).fill(null));
    const reserved = Array.from({ length: SIZE }, () => new Array(SIZE).fill(false));

    function setFunc(r, c, dark) {
      if (r >= 0 && r < SIZE && c >= 0 && c < SIZE) {
        grid[r][c] = dark;
        reserved[r][c] = true;
      }
    }

    function placeFinder(topR, leftC) {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const rr = topR + r;
          const cc = leftC + c;
          if (rr < 0 || rr >= SIZE || cc < 0 || cc >= SIZE) continue;
          const inBox = r >= 0 && r <= 6 && c >= 0 && c <= 6;
          const border = r === 0 || r === 6 || c === 0 || c === 6;
          const center = r >= 2 && r <= 4 && c >= 2 && c <= 4;
          setFunc(rr, cc, inBox && (border || center));
        }
      }
    }

    placeFinder(0, 0);
    placeFinder(0, SIZE - 7);
    placeFinder(SIZE - 7, 0);

    // Alignment pattern para versão 3 em (22, 22)
    for (let r = -2; r <= 2; r++) {
      for (let c = -2; c <= 2; c++) {
        const dark = Math.max(Math.abs(r), Math.abs(c)) !== 1;
        setFunc(22 + r, 22 + c, dark);
      }
    }

    // Timing patterns
    for (let i = 8; i < SIZE - 8; i++) {
      setFunc(6, i, i % 2 === 0);
      setFunc(i, 6, i % 2 === 0);
    }

    // Dark module
    setFunc(SIZE - 8, 8, true);

    // Reserva área de format info (máscara 0 -> format bits 0x77C2)
    const fmt = 0x77C2;
    for (let i = 0; i < 6; i++) setFunc(8, i, ((fmt >> (14 - i)) & 1) === 1);
    setFunc(8, 7, ((fmt >> 8) & 1) === 1);
    setFunc(8, 8, ((fmt >> 7) & 1) === 1);
    setFunc(7, 8, ((fmt >> 6) & 1) === 1);
    for (let i = 0; i < 6; i++) setFunc(5 - i, 8, ((fmt >> (5 - i)) & 1) === 1);

    for (let i = 0; i < 7; i++) setFunc(SIZE - 1 - i, 8, ((fmt >> (14 - i)) & 1) === 1);
    for (let i = 0; i < 8; i++) setFunc(8, SIZE - 8 + i, ((fmt >> (7 - i)) & 1) === 1);

    // Preenche bits de dados com máscara 0 ((r + c) % 2 === 0)
    const bitStream = [];
    for (let i = 0; i < finalBytes.length; i++) {
      for (let b = 7; b >= 0; b--) bitStream.push((finalBytes[i] >> b) & 1);
    }

    let bitPos = 0;
    let upward = true;
    for (let col = SIZE - 1; col >= 1; col -= 2) {
      if (col === 6) col = 5;
      const rows = upward
        ? Array.from({ length: SIZE }, (_, idx) => SIZE - 1 - idx)
        : Array.from({ length: SIZE }, (_, idx) => idx);
      for (const r of rows) {
        for (const c of [col, col - 1]) {
          if (reserved[r][c]) continue;
          const rawBit = bitPos < bitStream.length ? bitStream[bitPos++] : 0;
          const maskBit = (r + c) % 2 === 0 ? 1 : 0;
          grid[r][c] = (rawBit ^ maskBit) === 1;
        }
      }
      upward = !upward;
    }

    return grid;
  }

  window.renderPixQrToCanvas = function (canvasId, payload) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || !canvas.getContext) return;
    const ctx = canvas.getContext('2d');
    const size = canvas.width || 144;
    canvas.width = size;
    canvas.height = size;

    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);

    try {
      const grid = buildQrMatrix(payload);
      const quiet = 2;
      const total = SIZE + quiet * 2;
      const modSize = size / total;
      ctx.fillStyle = '#0f172a';
      for (let r = 0; r < SIZE; r++) {
        for (let c = 0; c < SIZE; c++) {
          if (grid[r][c]) {
            const x = Math.floor((c + quiet) * modSize);
            const y = Math.floor((r + quiet) * modSize);
            const w = Math.ceil((c + quiet + 1) * modSize) - x;
            const h = Math.ceil((r + quiet + 1) * modSize) - y;
            ctx.fillRect(x, y, w, h);
          }
        }
      }
    } catch (_err) {
      // Fallback visual caso payload exceda capacidade da versão 3
      ctx.strokeStyle = '#0f172a';
      ctx.lineWidth = 3;
      ctx.strokeRect(8, 8, size - 16, size - 16);
      ctx.fillStyle = '#0f172a';
      ctx.font = 'bold 11px monospace';
      ctx.fillText('PIX EMV', 18, 28);
      ctx.font = '10px monospace';
      ctx.fillText(String(payload || '').slice(0, 18), 18, 48);
    }
  };
})();