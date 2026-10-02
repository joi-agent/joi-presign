// JSON.parse rounds integers above 2^53. Amounts and deadlines are often bigger, so integer
// literals with more than 15 digits are turned into strings before parsing; core.int() reads both.

export function parseJsonLossless(text) {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < n && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (ch === "-" || (ch >= "0" && ch <= "9")) {
      let j = i + 1;
      while (j < n && /[0-9.eE+\-]/.test(text[j])) j++;
      const tok = text.slice(i, j);
      out += /^-?\d{16,}$/.test(tok) ? `"${tok}"` : tok;
      i = j;
    } else {
      out += ch;
      i++;
    }
  }
  return JSON.parse(out);
}
