// A small, tolerant HTML parser (tokenizer + tree builder), readable-content extraction, Markdown rendering and
// page metadata. No dependencies; built for typical article and docs pages, not for the full HTML5 algorithm.

const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
// Raw-text elements: their content is never parsed as tags. All of them are dropped from the tree except title/textarea.
const RAW = new Set(["script", "style", "noscript", "template", "iframe", "noembed", "noframes", "xmp", "title", "textarea"]);
const KEEP_RAW = new Set(["title", "textarea"]);
// Opening one of these closes an open <p> (HTML's "close a p element" rule, simplified).
const CLOSES_P = new Set([
  "address", "article", "aside", "blockquote", "details", "div", "dl", "fieldset", "figcaption", "figure", "footer", "form",
  "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "main", "menu", "nav", "ol", "p", "pre", "section", "table", "ul",
]);
const AUTO_CLOSE = { li: ["li"], dt: ["dt", "dd"], dd: ["dt", "dd"], tr: ["tr", "td", "th"], td: ["td", "th"], th: ["td", "th"], option: ["option"], thead: ["tbody", "tfoot"], tbody: ["thead", "tbody", "tfoot"], tfoot: ["thead", "tbody"] };
// An auto-close search stops at these (a nested list's <li> must not close the outer one).
const SCOPE = { li: new Set(["ul", "ol", "menu"]), dt: new Set(["dl"]), dd: new Set(["dl"]), tr: new Set(["table"]), td: new Set(["tr", "table"]), th: new Set(["tr", "table"]), option: new Set(["select"]), thead: new Set(["table"]), tbody: new Set(["table"]), tfoot: new Set(["table"]) };

const NAMED = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ensp: " ", emsp: " ", thinsp: " ", shy: "", zwnj: "", zwj: "",
  mdash: "—", ndash: "–", hellip: "…", lsquo: "‘", rsquo: "’", sbquo: "‚", ldquo: "“", rdquo: "”", bdquo: "„",
  laquo: "«", raquo: "»", lsaquo: "‹", rsaquo: "›", middot: "·", bull: "•", copy: "©", reg: "®", trade: "™", deg: "°",
  times: "×", divide: "÷", plusmn: "±", minus: "−", euro: "€", pound: "£", yen: "¥", cent: "¢", sect: "§", para: "¶",
  frac12: "½", frac14: "¼", frac34: "¾", sup2: "²", sup3: "³", micro: "µ", larr: "←", rarr: "→", uarr: "↑", darr: "↓",
  harr: "↔", check: "✓", hearts: "♥", iexcl: "¡", iquest: "¿", prime: "′", Prime: "″", dagger: "†", Dagger: "‡",
  aacute: "á", eacute: "é", iacute: "í", oacute: "ó", uacute: "ú", agrave: "à", egrave: "è", ograve: "ò", auml: "ä",
  ouml: "ö", uuml: "ü", Auml: "Ä", Ouml: "Ö", Uuml: "Ü", szlig: "ß", ccedil: "ç", ntilde: "ñ", aring: "å", oslash: "ø",
  aelig: "æ", Eacute: "É",
};
// Named references browsers also accept without the semicolon (the common legacy ones).
const LEGACY = new Set(["amp", "lt", "gt", "quot", "nbsp", "copy", "reg"]);

export function decodeEntities(s) {
  if (!s.includes("&")) return s;
  return s.replace(/&(#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31})(;?)/g, (m, ref, semi) => {
    if (ref[0] === "#") {
      const cp = ref[1] === "x" || ref[1] === "X" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      if (!cp || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return "�";
      return String.fromCodePoint(cp);
    }
    if (!(ref in NAMED) || (!semi && !LEGACY.has(ref))) return m;
    return NAMED[ref];
  });
}

/** Attribute parser: a hand-written scan (regex-free; this is the hot path on big pages). Names are lowercased, the
 *  first occurrence of a name wins, values have entities decoded. */
function parseAttrs(src) {
  const attrs = {};
  const n = src.length;
  let i = 0;
  while (i < n) {
    let c = src.charCodeAt(i);
    while (i < n && (c === 32 || c === 9 || c === 10 || c === 13 || c === 12 || c === 47)) c = src.charCodeAt(++i);
    if (i >= n) break;
    const ns = i;
    while (i < n) {
      c = src.charCodeAt(i);
      if (c === 32 || c === 9 || c === 10 || c === 13 || c === 12 || c === 61 || c === 62 || c === 47) break;
      i++;
    }
    if (i === ns) { i++; continue; }
    const name = src.slice(ns, i).toLowerCase();
    while (i < n && ((c = src.charCodeAt(i)) === 32 || c === 9 || c === 10 || c === 13 || c === 12)) i++;
    let value = "";
    if (i < n && src.charCodeAt(i) === 61) {
      i++;
      while (i < n && ((c = src.charCodeAt(i)) === 32 || c === 9 || c === 10 || c === 13 || c === 12)) i++;
      c = src.charCodeAt(i);
      if (c === 34 || c === 39) {
        const end = src.indexOf(c === 34 ? '"' : "'", i + 1);
        value = src.slice(i + 1, end === -1 ? n : end);
        i = end === -1 ? n : end + 1;
      } else {
        const vs = i;
        while (i < n && (c = src.charCodeAt(i)) !== 32 && c !== 9 && c !== 10 && c !== 13 && c !== 12 && c !== 62) i++;
        value = src.slice(vs, i);
      }
    }
    if (!(name in attrs)) attrs[name] = value.indexOf("&") === -1 ? value : decodeEntities(value);
  }
  return attrs;
}

/** Index of the ">" that ends a tag starting at i (just after "<"), ignoring ">" inside quoted attribute values.
 *  A quote only opens right after "=" (whitespace allowed), so a stray apostrophe can't swallow the document. */
function tagEnd(html, i) {
  let quote = 0;
  let lastNonSpace = 0;
  for (let j = i; j < html.length; j++) {
    const c = html.charCodeAt(j);
    if (quote) { if (c === quote) quote = 0; continue; }
    if (c === 62) return j; // >
    if ((c === 34 || c === 39) && lastNonSpace === 61) { quote = c; continue; } // " or ' after =
    if (c !== 32 && c !== 9 && c !== 10 && c !== 13) lastNonSpace = c;
  }
  return -1;
}

function el(tag, attrs, parent) {
  return { tag, attrs, children: [], parent };
}

/** Parse HTML into a tree of {tag, attrs, children, parent} and string text nodes. Root tag is "#document". */
export function parseHtml(html) {
  const root = el("#document", {}, null);
  const stack = [root];
  const top = () => stack[stack.length - 1];
  const len = html.length;
  let pos = 0;

  const close = (tag) => {
    for (let i = stack.length - 1; i > 0; i--) {
      if (stack[i].tag === tag) { stack.length = i; return true; }
    }
    return false;
  };
  const autoClose = (tag) => {
    const closers = AUTO_CLOSE[tag];
    if (!closers) return;
    const scope = SCOPE[tag];
    for (let i = stack.length - 1; i > 0; i--) {
      const t = stack[i].tag;
      if (closers.includes(t)) { stack.length = i; return; }
      if (scope.has(t)) return;
    }
  };

  while (pos < len) {
    const lt = html.indexOf("<", pos);
    if (lt === -1) { top().children.push(decodeEntities(html.slice(pos))); break; }
    if (lt > pos) top().children.push(decodeEntities(html.slice(pos, lt)));
    if (html.startsWith("<!--", lt)) {
      const end = html.indexOf("-->", lt + 4);
      pos = end === -1 ? len : end + 3;
      continue;
    }
    if (html[lt + 1] === "!" || html[lt + 1] === "?") {
      const end = html.indexOf(">", lt + 2);
      pos = end === -1 ? len : end + 1;
      continue;
    }
    const gt = tagEnd(html, lt + 1);
    if (gt === -1) { top().children.push(decodeEntities(html.slice(lt))); break; }
    const body = html.slice(lt + 1, gt);
    pos = gt + 1;
    if (body[0] === "/") {
      const tag = body.slice(1).trim().split(/\s/)[0].toLowerCase();
      if (tag === "p" && !stack.some((n) => n.tag === "p")) top().children.push(el("p", {}, top())); // stray </p>
      else close(tag);
      continue;
    }
    const m = /^([A-Za-z][A-Za-z0-9:-]*)/.exec(body);
    if (!m) { top().children.push(decodeEntities("<" + body + ">")); continue; }
    const tag = m[1].toLowerCase();
    const selfClosing = body.endsWith("/");
    const attrs = parseAttrs(body.slice(m[1].length, selfClosing ? -1 : undefined));
    if (CLOSES_P.has(tag)) {
      for (let i = stack.length - 1; i > 0; i--) {
        const t = stack[i].tag;
        if (t === "p") { stack.length = i; break; }
        if (t === "button" || t === "td" || t === "th" || t === "li" || t === "blockquote" || t === "div" || t === "section" || t === "article") break;
      }
    }
    autoClose(tag);
    if (RAW.has(tag)) {
      const endRe = new RegExp(`</${tag}\\s*>`, "ig");
      endRe.lastIndex = pos;
      const em = endRe.exec(html);
      const content = html.slice(pos, em ? em.index : len);
      pos = em ? endRe.lastIndex : len;
      if (KEEP_RAW.has(tag)) {
        const node = el(tag, attrs, top());
        node.children.push(decodeEntities(content));
        top().children.push(node);
      }
      continue;
    }
    const node = el(tag, attrs, top());
    top().children.push(node);
    if (!VOID.has(tag) && !selfClosing) stack.push(node);
  }
  return root;
}

// ---------------------------------------------------------------- tree helpers

/** Visit every element below node, depth-first, without recursion or generators (fast on big pages). */
export function each(node, fn) {
  const stack = [];
  const ch0 = node.children;
  for (let i = ch0.length - 1; i >= 0; i--) if (typeof ch0[i] !== "string") stack.push(ch0[i]);
  while (stack.length) {
    const n = stack.pop();
    if (fn(n) === false) return;
    const ch = n.children;
    for (let i = ch.length - 1; i >= 0; i--) if (typeof ch[i] !== "string") stack.push(ch[i]);
  }
}

export function* walk(node) {
  const all = [];
  each(node, (n) => { all.push(n); });
  yield* all;
}

export function find(node, pred) {
  let hit = null;
  each(node, (n) => {
    if (pred(n)) { hit = n; return false; }
    return true;
  });
  return hit;
}

export function textOf(node) {
  if (typeof node === "string") return node;
  const parts = [];
  const stack = [node];
  while (stack.length) {
    const n = stack.pop();
    if (typeof n === "string") { parts.push(n); continue; }
    for (let i = n.children.length - 1; i >= 0; i--) stack.push(n.children[i]);
  }
  return parts.join("");
}

const squash = (s) => s.replace(/\s+/g, " ").trim();

// ---------------------------------------------------------------- boilerplate removal and content selection

const DROP_TAGS = new Set(["svg", "canvas", "nav", "footer", "aside", "form", "button", "select", "input", "textarea", "dialog", "object", "embed", "audio", "video", "map", "math", "link", "meta", "head", "title", "style", "script"]);
const DROP_ROLES = new Set(["navigation", "contentinfo", "complementary", "search", "dialog", "alertdialog", "banner", "menu", "menubar", "toolbar"]);
const JUNK_WORDS = new Set([
  "nav", "navbar", "navigation", "menu", "footer", "sidebar", "cookie", "cookies", "consent", "advert", "advertisement",
  "ads", "ad", "promo", "share", "sharing", "social", "newsletter", "subscribe", "breadcrumb", "breadcrumbs", "related",
  "comment", "comments", "popup", "modal", "skip", "toc", "masthead", "banner", "noprint", "sr-only", "visually-hidden",
  "editsection", "navbox", "jump", "printfooter", "catlinks", "sitenotice",
]);

const ESC = (w) => w.replace(/[-]/g, "\\-");
const JUNK_TOKEN_RE = new RegExp(`(?:^|\\s)(?:${[...JUNK_WORDS].map(ESC).join("|")})(?=\\s|$)`);
const JUNK_PART_RE = new RegExp(`(?:^|[\\s_-])(?:${[...JUNK_WORDS].filter((w) => w.length > 2 && !w.includes("-")).join("|")})(?=[\\s_-]|$)`);

function isJunk(n, insideContent) {
  if (DROP_TAGS.has(n.tag)) return true;
  if (n.tag === "header" && !insideContent) return true;
  const a = n.attrs;
  if (!a.class && !a.id && !a.role && !a.style && !("hidden" in a) && !a["aria-hidden"]) return false;
  if ("hidden" in a || a["aria-hidden"] === "true") return true;
  if (a.role && DROP_ROLES.has(a.role.toLowerCase())) return true;
  if (a.style && /display\s*:\s*none|visibility\s*:\s*hidden/i.test(a.style)) return true;
  const names = `${a.class || ""} ${a.id || ""}`.toLowerCase();
  return JUNK_TOKEN_RE.test(names) || JUNK_PART_RE.test(names);
}

/** Remove boilerplate in place. Article/main containers and their ancestors are never removed. */
function prune(node, insideContent = false) {
  node.children = node.children.filter((c) => {
    if (typeof c === "string") return true;
    const inside = insideContent || c.tag === "article" || c.tag === "main";
    if (c.tag !== "article" && c.tag !== "main" && c.tag !== "body" && c.tag !== "html" && isJunk(c, insideContent)) return false;
    prune(c, inside);
    return true;
  });
}

function textLength(node) {
  return squash(textOf(node)).length;
}

/** The node holding the main content: the biggest <article>, else <main>, else [role=main], else <body>. */
export function selectContent(doc) {
  const body = find(doc, (n) => n.tag === "body") || doc;
  prune(body);
  const articles = [...walk(body)].filter((n) => n.tag === "article");
  if (articles.length) return articles.reduce((a, b) => (textLength(b) > textLength(a) ? b : a));
  return find(body, (n) => n.tag === "main") || find(body, (n) => (n.attrs.role || "").toLowerCase() === "main") || body;
}

// ---------------------------------------------------------------- Markdown

const BLOCK = new Set([
  "p", "div", "section", "article", "main", "header", "footer", "aside", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol",
  "li", "pre", "blockquote", "table", "thead", "tbody", "tfoot", "tr", "hr", "figure", "figcaption", "dl", "dt", "dd",
  "address", "details", "summary", "center", "body", "html", "hgroup", "fieldset", "legend", "menu", "caption",
]);

function escapeText(s) {
  return s.replace(/([\\*`])/g, "\\$1");
}

/** Escape what would start a Markdown block at the beginning of a line. */
function escapeLineStart(line) {
  return line.replace(/^(\s*)(#{1,6}\s|>|[-+]\s|\d+[.)]\s)/, (m, sp, mark) => sp + "\\" + mark);
}

function wrap(marker, s) {
  if (!s.trim()) return s;
  const lead = /^\s/.test(s) ? " " : "";
  const trail = /\s$/.test(s) ? " " : "";
  return `${lead}${marker}${s.trim()}${marker}${trail}`;
}

function absUrl(href, base) {
  if (!href) return null;
  const h = href.trim();
  if (!h || /^(javascript|data|vbscript):/i.test(h)) return null;
  try {
    const u = new URL(h, base);
    if (!/^(https?|mailto):$/.test(u.protocol)) return null;
    return u.toString();
  } catch {
    return null;
  }
}

class Renderer {
  constructor(baseUrl) {
    this.base = baseUrl;
    this.links = 0;
  }

  inline(node) {
    if (typeof node === "string") return escapeText(node.replace(/\s+/g, " "));
    const t = node.tag;
    if (t === "br") return "\n";
    if (t === "img") {
      const src = absUrl(node.attrs.src, this.base);
      if (!src || src.length > 2000) return "";
      const alt = squash(node.attrs.alt || "").replace(/[[\]]/g, "");
      return `![${alt}](${src})`;
    }
    if (t === "wbr") return "";
    if (BLOCK.has(t)) return " " + this.children(node) + " ";
    const inner = this.children(node);
    if (t === "a") {
      const text = inner.replace(/\s+/g, " ");
      if (!text.trim()) return "";
      const raw = (node.attrs.href || "").trim();
      if (raw.startsWith("#")) return text;
      const href = absUrl(raw, this.base);
      if (!href) return text;
      this.links++;
      return wrapLink(text, href);
    }
    if (t === "strong" || t === "b") return wrap("**", inner);
    if (t === "em" || t === "i" || t === "cite") return wrap("*", inner);
    if (t === "del" || t === "s" || t === "strike") return wrap("~~", inner);
    if (t === "code" || t === "kbd" || t === "samp" || t === "tt") {
      const raw = squash(textOf(node));
      if (!raw) return "";
      const fence = raw.includes("`") ? "``" : "`";
      const pad = raw.startsWith("`") || raw.endsWith("`") ? " " : "";
      return `${fence}${pad}${raw}${pad}${fence}`;
    }
    if (t === "q") return `“${inner.trim()}”`;
    if (t === "sup" && /^\s*\[\s*\d+\s*\]\s*$/.test(textOf(node))) return ""; // citation markers
    return inner;
  }

  children(node) {
    let s = "";
    for (const c of node.children) s += this.inline(c);
    return s;
  }

  /** Render a node's children as Markdown blocks. */
  blocks(node, out = []) {
    let para = "";
    const flush = () => {
      const p = para.split("\n").map((l) => l.replace(/[ \t]+/g, " ").trim()).filter(Boolean).join("\n");
      if (p) out.push(p.split("\n").map(escapeLineStart).join("\n"));
      para = "";
    };
    for (const c of node.children) {
      if (typeof c === "string" || !BLOCK.has(c.tag)) {
        para += this.inline(c);
        continue;
      }
      flush();
      this.block(c, out);
    }
    flush();
    return out;
  }

  block(n, out) {
    const t = n.tag;
    if (/^h[1-6]$/.test(t)) {
      const text = squash(this.children(n));
      if (text) out.push(`${"#".repeat(Number(t[1]))} ${text}`);
      return;
    }
    if (t === "hr") { out.push("---"); return; }
    if (t === "pre") { out.push(this.pre(n)); return; }
    if (t === "ul" || t === "ol" || t === "menu") { const l = this.list(n); if (l) out.push(l); return; }
    if (t === "blockquote") {
      const inner = this.blocks(n, []).join("\n\n");
      if (inner) out.push(inner.split("\n").map((l) => (l ? `> ${l}` : ">")).join("\n"));
      return;
    }
    if (t === "table") { const tb = this.table(n); if (tb) out.push(tb); return; }
    if (t === "figcaption" || t === "caption") {
      const text = squash(this.children(n));
      if (text) out.push(`*${text}*`);
      return;
    }
    if (t === "dt") {
      const text = squash(this.children(n));
      if (text) out.push(`**${text}**`);
      return;
    }
    if (t === "dd") {
      const inner = this.blocks(n, []).join("\n");
      if (inner) out.push(`: ${inner}`);
      return;
    }
    this.blocks(n, out);
  }

  pre(n) {
    const code = find(n, (c) => c.tag === "code");
    const cls = `${n.attrs.class || ""} ${code ? code.attrs.class || "" : ""}`;
    const lang = (/(?:^|\s)(?:language|lang)-([A-Za-z0-9_+#.-]+)/.exec(cls) || [])[1] || "";
    let text = textOf(n).replace(/\r\n?/g, "\n").replace(/^\n/, "").replace(/\s+$/, "");
    let fence = "```";
    while (text.includes(fence)) fence += "`";
    return `${fence}${lang}\n${text}\n${fence}`;
  }

  list(n, depth = 0) {
    const ordered = n.tag === "ol";
    let i = Number.parseInt(n.attrs.start || "1", 10);
    if (!Number.isFinite(i)) i = 1;
    const lines = [];
    for (const c of n.children) {
      if (typeof c === "string") {
        if (c.trim()) lines.push(`${"  ".repeat(depth)}- ${escapeText(squash(c))}`);
        continue;
      }
      if (c.tag !== "li") {
        if (c.tag === "ul" || c.tag === "ol") lines.push(this.list(c, depth + 1));
        continue;
      }
      const marker = ordered ? `${i++}. ` : "- ";
      const indent = "  ".repeat(depth);
      const inner = [];
      let para = "";
      const flush = () => { const p = squash(para); if (p) inner.push(p); para = ""; };
      for (const k of c.children) {
        if (typeof k !== "string" && (k.tag === "ul" || k.tag === "ol")) { flush(); inner.push({ nested: this.list(k, depth + 1) }); continue; }
        if (typeof k !== "string" && BLOCK.has(k.tag)) { flush(); for (const b of this.blocks({ children: [k] }, [])) inner.push(b.replace(/\n/g, " ")); continue; }
        para += this.inline(k);
      }
      flush();
      if (!inner.length) continue;
      let first = true;
      for (const part of inner) {
        if (typeof part === "object") { if (part.nested) lines.push(part.nested); continue; }
        lines.push(first ? `${indent}${marker}${part}` : `${indent}${" ".repeat(marker.length)}${part}`);
        first = false;
      }
    }
    return lines.filter(Boolean).join("\n");
  }

  table(n) {
    const rows = [];
    const visit = (node) => {
      for (const c of node.children) {
        if (typeof c === "string") continue;
        if (c.tag === "table") continue; // nested tables are skipped
        if (c.tag === "tr") {
          const cells = c.children.filter((k) => typeof k !== "string" && (k.tag === "td" || k.tag === "th"));
          if (cells.length) rows.push({ head: cells.every((k) => k.tag === "th"), cells: cells.map((k) => squash(this.children(k)).replace(/\|/g, "\\|") || " ") });
        } else visit(c);
      }
    };
    visit(n);
    if (!rows.length) return "";
    const width = Math.max(...rows.map((r) => r.cells.length));
    const pad = (cells) => [...cells, ...Array(width - cells.length).fill(" ")];
    const head = rows[0];
    const body = rows.slice(1);
    const line = (cells) => `| ${pad(cells).join(" | ")} |`;
    return [line(head.cells), `| ${Array(width).fill("---").join(" | ")} |`, ...body.map((r) => line(r.cells))].join("\n");
  }
}

function wrapLink(text, href) {
  const lead = /^\s/.test(text) ? " " : "";
  const trail = /\s$/.test(text) ? " " : "";
  const t = text.trim();
  return `${lead}[${t}](${href.replace(/\)/g, "%29").replace(/ /g, "%20")})${trail}`;
}

/** Markdown for a content node, and the number of links rendered. */
export function toMarkdown(node, baseUrl) {
  const r = new Renderer(baseUrl);
  const blocks = r.blocks(node, []);
  const md = blocks.join("\n\n").replace(/\n{3,}/g, "\n\n").trim();
  return { markdown: md, links: r.links };
}

export function wordCount(markdown) {
  const plain = markdown.replace(/\]\([^)]*\)/g, "]").replace(/```[^\n]*\n/g, "");
  return (plain.match(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu) || []).length;
}

// ---------------------------------------------------------------- metadata

/** One pass over the document: meta values (first wins), link rels, <base>, <title>, <html>, microdata hints. */
export function scanHead(doc, pageUrl) {
  const meta = {};
  const links = [];
  let base = null, title = null, html = null, itempropAuthor = null, datePublished = null, relAuthor = null;
  each(doc, (n) => {
    const t = n.tag;
    if (t === "meta") {
      const a = n.attrs;
      const key = (a.property || a.name || a["http-equiv"] || a.itemprop || "").toLowerCase().trim();
      if (key && a.content !== undefined && !(key in meta)) meta[key] = a.content.trim();
    } else if (t === "link") {
      if (n.attrs.rel) links.push(n);
    } else if (t === "base") {
      if (!base && n.attrs.href) base = n.attrs.href;
    } else if (t === "title") {
      if (!title) title = n;
    } else if (t === "html") {
      if (!html) html = n;
    } else if (t === "a" && !relAuthor && n.attrs.rel && n.attrs.rel.toLowerCase().split(/\s+/).includes("author")) {
      relAuthor = n;
    }
    const ip = n.attrs.itemprop;
    if (ip) {
      if (!itempropAuthor && ip.split(/\s+/).includes("author")) itempropAuthor = n;
      if (!datePublished && ip === "datePublished") datePublished = n;
    }
  });
  const baseUrl = (base && absUrl(base, pageUrl)) || pageUrl;
  const rels = [];
  for (const n of links) {
    const href = absUrl(n.attrs.href, baseUrl);
    if (href) rels.push({ rel: n.attrs.rel.toLowerCase().split(/\s+/), href, sizes: n.attrs.sizes || null, type: n.attrs.type || null });
  }
  return { meta, rels, base: baseUrl, title, html, itempropAuthor, datePublished, relAuthor };
}

export function metaMap(doc) {
  return scanHead(doc, "https://invalid.invalid/").meta;
}

export function linkRels(doc, baseUrl) {
  return scanHead(doc, baseUrl).rels;
}

export function baseUrlOf(doc, pageUrl) {
  return scanHead(doc, pageUrl).base;
}

const looksLikeUrl = (s) => /^https?:\/\//i.test(s);

export function pageMetadata(doc, pageUrl, content = null, scanned = null) {
  const h = scanned || scanHead(doc, pageUrl);
  const meta = h.meta;
  const h1 = find(content || doc, (n) => n.tag === "h1");
  const title = meta["og:title"] || (h.title && squash(textOf(h.title))) || (h1 && squash(textOf(h1))) || null;
  let byline = meta.author || (meta["article:author"] && !looksLikeUrl(meta["article:author"]) ? meta["article:author"] : null);
  if (!byline && h.itempropAuthor) {
    const au = h.itempropAuthor;
    const nameNode = find(au, (n) => (n.attrs.itemprop || "") === "name");
    byline = (nameNode && (nameNode.attrs.content || squash(textOf(nameNode)))) || au.attrs.content || squash(textOf(au)) || null;
  }
  if (!byline && h.relAuthor) byline = squash(textOf(h.relAuthor)) || null;
  let published = meta["article:published_time"] || meta.datepublished || meta.date || meta.pubdate || meta.publishdate || meta["dc.date"] || meta["dc.date.issued"] || null;
  if (!published && h.datePublished) {
    const dp = h.datePublished;
    published = dp.attrs.content || dp.attrs.datetime || squash(textOf(dp)) || null;
  }
  if (!published && content) {
    const t = find(content, (n) => n.tag === "time" && n.attrs.datetime);
    if (t) published = t.attrs.datetime;
  }
  const canonical = (h.rels.find((l) => l.rel.includes("canonical")) || {}).href || null;
  const language = (h.html && h.html.attrs.lang) || meta["content-language"] || meta["og:locale"] || null;
  return {
    title: title ? squash(title).slice(0, 500) : null,
    byline: byline ? squash(byline).slice(0, 200) : null,
    published: published ? published.slice(0, 64) : null,
    canonical,
    language: language ? language.slice(0, 35) : null,
    description: meta.description || meta["og:description"] || null,
    site_name: meta["og:site_name"] || null,
    meta, rels: h.rels, base: h.base, titleNode: h.title, htmlNode: h.html,
  };
}
