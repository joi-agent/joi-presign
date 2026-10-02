import test from "node:test";
import assert from "node:assert/strict";
import { handle, openapi, _resetRateLimit } from "../src/worker.js";
import { DEFAULTS, b64decodeJson, b64encodeJson } from "../src/x402.js";
import { Refused, SafeFetcher } from "../src/fetchsafe.js";
import { LookupUnavailable } from "../src/profile.js";
import { decodeEntities, parseHtml, selectContent, toMarkdown, wordCount, pageMetadata, find, textOf, scanHead } from "../src/html.js";
import { PARSE_MAX_CHARS, READER_UA, headOnly, parsePageTarget, prepareHtml, readPage, urlMeta } from "../src/readpage.js";
import { DOH_URL, emailCheck, parseDmarc, parseEmailTarget, parseSpf, txtData } from "../src/emailcheck.js";

const ORIGIN = "https://joi-presign.example.workers.dev";
test.beforeEach(() => _resetRateLimit());

// ---------------------------------------------------------------- helpers

function fakeFetch(routes = {}, { facilitator = true, fail = [] } = {}) {
  const calls = [];
  const f = async (url, init = {}) => {
    const method = (init.method || "GET").toUpperCase();
    calls.push({ url, method, headers: init.headers || {} });
    if (facilitator && url.endsWith("/verify")) return Response.json({ isValid: true });
    if (facilitator && url.endsWith("/settle")) return Response.json({ success: true, transaction: "0x" + "cd".repeat(32), network: "eip155:8453" });
    if (fail.includes(url)) throw new TypeError("network down");
    const r = routes[`${method} ${url}`] ?? routes[url];
    if (!r) return new Response("not found", { status: 404, headers: { "Content-Type": "text/plain" } });
    return typeof r === "function" ? r(init) : r.clone();
  };
  f.calls = calls;
  return f;
}
const html = (body, headers = {}, status = 200) => new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", ...headers } });
const text = (body, status = 200, ct = "text/plain") => new Response(body, { status, headers: { "Content-Type": ct } });

function payment(resource) {
  return b64encodeJson({
    x402Version: 2,
    resource: { url: ORIGIN + resource },
    accepted: { scheme: "exact", network: "eip155:8453", amount: DEFAULTS.amount, asset: DEFAULTS.asset, payTo: DEFAULTS.payTo, maxTimeoutSeconds: 60, extra: DEFAULTS.extra },
    payload: { signature: "0x" + "ab".repeat(65), authorization: { from: "0x" + "99".repeat(20), to: DEFAULTS.payTo, value: DEFAULTS.amount, validAfter: "0", validBefore: "9999999999", nonce: "0x" + "01".repeat(32) } },
  });
}
const req = (pathq, { method = "GET", body, pay } = {}) => new Request(ORIGIN + pathq, {
  method,
  headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(pay ? { "PAYMENT-SIGNATURE": payment(pathq.split("?")[0]) } : {}) },
  body: body === undefined ? undefined : JSON.stringify(body),
});
const fetcher = (f, maxBytes = 2 * 1024 * 1024) => new SafeFetcher({ fetchFn: f, maxRequests: 30, maxBytes });
const settles = (f) => f.calls.filter((c) => c.url.endsWith("/settle")).length;
const verifies = (f) => f.calls.filter((c) => c.url.endsWith("/verify")).length;

const ARTICLE = `<!doctype html>
<html lang="en-GB"><head>
<meta charset="utf-8"><title>Fallback title | Site</title>
<meta property="og:title" content="How &amp; why we test">
<meta name="author" content="Ada Lovelace">
<meta property="article:published_time" content="2026-09-30T08:00:00Z">
<meta name="description" content="A test article.">
<link rel="canonical" href="/posts/how-we-test">
<base href="https://blog.example.com/posts/">
<script>var x = "</div><p>not content</p>";</script>
<style>p { color: red }</style>
</head><body>
<header class="site-header"><a href="/">Home</a> Site name</header>
<nav><a href="/a">Menu A</a><a href="/b">Menu B</a></nav>
<div class="cookie-banner">We use cookies</div>
<main>
<article>
<h1>How &amp; why we test</h1>
<p class="byline">By <a rel="author" href="/ada">Ada</a> · <time datetime="2026-09-30">30 Sep</time></p>
<p>Testing is <strong>important</strong> and <em>fun</em>. See <a href="guide.html">the guide</a> and <a href="#top">top</a>.
Use <code>npm test</code> to run it.<br>Second line.</p>
<h2>Steps</h2>
<ol start="3"><li>Write a test<li>Run it<ul><li>locally</li><li>in CI</li></ul></li></ol>
<ul><li>Alpha</li><li><p>Beta</p></li></ul>
<pre><code class="language-js">const a = 1 &lt; 2;
console.log(a);</code></pre>
<blockquote><p>Quote one.</p><p>Quote two.</p></blockquote>
<table><tr><th>Name</th><th>Value</th></tr><tr><td>a|b</td><td>1</td></tr><tr><td>c</td></tr></table>
<p><img src="/img/x.png" alt="An [x] image"> Caption text 5 * 3.</p>
<aside>Related posts</aside>
<div class="share-buttons">Share this</div>
<p>Price: 5 * 3 = 15 and # not a heading.</p>
<footer>Article footer</footer>
</article>
</main>
<footer>Site footer © 2026</footer>
</body></html>`;

// ---------------------------------------------------------------- html.js

test("tokenizer: quoted '>' inside attributes, entities, void and self-closing tags, implicit closes, raw text", () => {
  const doc = parseHtml(`<div data-x='a>b' title="c > d"><p>one<p>two</div><ul><li>a<li>b</ul><img src=x.png alt="&lt;img&gt;"><br/><script>if (a<b) {}</script><textarea>&lt;kept&gt;</textarea>`);
  const div = find(doc, (n) => n.tag === "div");
  assert.equal(div.attrs["data-x"], "a>b");
  assert.equal(div.attrs.title, "c > d");
  assert.equal(div.children.filter((c) => typeof c !== "string" && c.tag === "p").length, 2);
  const ul = find(doc, (n) => n.tag === "ul");
  assert.equal(ul.children.filter((c) => c.tag === "li").length, 2);
  assert.equal(find(doc, (n) => n.tag === "img").attrs.alt, "<img>");
  assert.equal(find(doc, (n) => n.tag === "script"), null);
  assert.equal(textOf(find(doc, (n) => n.tag === "textarea")), "<kept>");
  // a stray apostrophe outside a value doesn't swallow the document
  const d2 = parseHtml(`<a title=Don't href="/x">link</a><p>after</p>`);
  assert.equal(textOf(find(d2, (n) => n.tag === "p")), "after");
});

test("decodeEntities: named, numeric, hex, legacy without semicolon, unknown left alone, invalid code points", () => {
  assert.equal(decodeEntities("a &amp; b &lt;c&gt; &#65;&#x42; &copy &hellip; &foo; &#0; &#xD800;"), "a & b <c> AB © … &foo; � �");
  assert.equal(decodeEntities("AT&T &ampx"), "AT&T &ampx"); // unknown names are left as written
});

test("readable Markdown: article chosen, boilerplate removed, formatting, lists, code, quotes, tables, links resolved via <base>", () => {
  const doc = parseHtml(ARTICLE);
  const content = selectContent(doc);
  assert.equal(content.tag, "article");
  const meta = pageMetadata(doc, "https://blog.example.com/posts/how-we-test", content);
  const { markdown, links } = toMarkdown(content, meta.base);
  for (const junk of ["Menu A", "We use cookies", "Related posts", "Share this", "Site footer", "Article footer", "not content", "color: red"]) {
    assert.ok(!markdown.includes(junk), `should not contain: ${junk}`);
  }
  assert.match(markdown, /^# How & why we test/);
  assert.match(markdown, /Testing is \*\*important\*\* and \*fun\*\. See \[the guide\]\(https:\/\/blog\.example\.com\/posts\/guide\.html\) and top\./);
  assert.match(markdown, /Use `npm test` to run it\.\nSecond line\./);
  assert.match(markdown, /## Steps/);
  assert.match(markdown, /3\. Write a test\n4\. Run it\n  - locally\n  - in CI/);
  assert.match(markdown, /- Alpha\n- Beta/);
  assert.match(markdown, /```js\nconst a = 1 < 2;\nconsole\.log\(a\);\n```/);
  assert.match(markdown, /> Quote one\.\n>\n> Quote two\./);
  assert.match(markdown, /\| Name \| Value \|\n\| --- \| --- \|\n\| a\\\|b \| 1 \|\n\| c \|   \|/);
  assert.match(markdown, /!\[An x image\]\(https:\/\/blog\.example\.com\/img\/x\.png\) Caption text 5 \\\* 3\./);
  assert.match(markdown, /Price: 5 \\\* 3 = 15 and # not a heading\./);
  assert.equal(links, 2); // guide + author; the in-page #top link is rendered as text
  assert.equal(meta.title, "How & why we test");
  assert.equal(meta.byline, "Ada Lovelace");
  assert.equal(meta.published, "2026-09-30T08:00:00Z");
  assert.equal(meta.canonical, "https://blog.example.com/posts/how-we-test");
  assert.equal(meta.language, "en-GB");
  assert.equal(meta.description, "A test article.");
  assert.ok(wordCount(markdown) > 40);
});

test("content selection: biggest article, else main, else role=main, else body; a line that looks like Markdown is escaped", () => {
  const big = parseHtml(`<body><article><p>short</p></article><article><p>this one is clearly the longest article on the page</p></article></body>`);
  assert.match(textOf(selectContent(big)), /longest/);
  const main = parseHtml(`<body><div>sidebar-ish</div><main><p>main text</p></main></body>`);
  assert.equal(selectContent(main).tag, "main");
  const role = parseHtml(`<body><div role="main"><p>role main</p></div><div>other</div></body>`);
  assert.equal(selectContent(role).attrs.role, "main");
  const body = parseHtml(`<body><p># hash start</p><p>- dash start</p><p>1. one</p></body>`);
  const md = toMarkdown(selectContent(body), "https://x.example/").markdown;
  assert.equal(md, "\\# hash start\n\n\\- dash start\n\n\\1. one");
});

test("wordCount ignores URLs and code fence markers; prepareHtml strips scripts/styles/svg/comments and caps the size; headOnly", () => {
  assert.equal(wordCount("Hello [world](https://a.example/b-c-d) it's 2026"), 4);
  const p = prepareHtml(`<p>a</p><!-- c --><script>x</script><SVG><path/></svg><style>s</style><p>b</p>`);
  assert.equal(p.html, "<p>a</p><p>b</p>");
  assert.equal(p.cut, false);
  const big = prepareHtml("<p>" + "x".repeat(PARSE_MAX_CHARS) + "</p><p>tail</p>");
  assert.equal(big.cut, true);
  assert.ok(big.html.length <= PARSE_MAX_CHARS);
  assert.equal(headOnly("<html><head><title>t</title></head><body>b</body>"), "<html><head><title>t</title>");
});

// ---------------------------------------------------------------- /read logic

const SITE = "https://site.example.com";

test("readPage: robots.txt disallow for joi-reader (or *) refuses with 451 and the page is never fetched", async () => {
  for (const robots of [`User-agent: joi-reader\nDisallow: /private`, `User-agent: *\nDisallow: /private`]) {
    const f = fakeFetch({ [`${SITE}/robots.txt`]: text(robots), [`${SITE}/private/page`]: html("<p>secret</p>") });
    await assert.rejects(readPage(parsePageTarget(`${SITE}/private/page`), fetcher(f)), (e) => {
      assert.ok(e instanceof Refused);
      assert.equal(e.status, 451);
      assert.equal(e.body.allowed, false);
      assert.equal(e.body.charged, false);
      assert.match(e.body.reason, /disallows/);
      return true;
    });
    assert.ok(!f.calls.some((c) => c.url === `${SITE}/private/page`), "page must not be fetched");
  }
  // a specific joi-reader group overrides "*"
  const f2 = fakeFetch({ [`${SITE}/robots.txt`]: text(`User-agent: *\nDisallow: /\n\nUser-agent: joi-reader\nAllow: /`), [`${SITE}/ok`]: html("<p>fine</p>") });
  const ok = await readPage(parsePageTarget(`${SITE}/ok`), fetcher(f2));
  assert.equal(ok.allowed, true);
  assert.equal(ok.robots.group, "joi-reader");
});

test("readPage: robots 404 = allowed, robots 5xx = refused, UA identifies joi-reader", async () => {
  const f = fakeFetch({ [`${SITE}/a`]: html("<html><head><title>T</title></head><body><p>Body text here.</p></body></html>") });
  const r = await readPage(parsePageTarget(`${SITE}/a`), fetcher(f));
  assert.equal(r.markdown, "Body text here.");
  assert.equal(r.title, "T");
  assert.match(r.robots.note, /HTTP 404/);
  assert.ok(f.calls.every((c) => c.headers["User-Agent"] === READER_UA));
  const f5 = fakeFetch({ [`${SITE}/robots.txt`]: text("oops", 503), [`${SITE}/a`]: html("<p>x</p>") });
  await assert.rejects(readPage(parsePageTarget(`${SITE}/a`), fetcher(f5)), (e) => e instanceof Refused && e.status === 451 && /503/.test(e.body.reason));
  assert.ok(!f5.calls.some((c) => c.url === `${SITE}/a`));
});

test("readPage: same-site redirect to a disallowed path is refused; error pages 422; PDFs 415; text/plain passes", async () => {
  const f = fakeFetch({
    [`${SITE}/robots.txt`]: text("User-agent: *\nDisallow: /members"),
    [`${SITE}/go`]: new Response(null, { status: 302, headers: { Location: "/members/area" } }),
    [`${SITE}/members/area`]: html("<p>members</p>"),
    [`${SITE}/missing`]: html("<p>Not found</p>", {}, 404),
    [`${SITE}/doc.pdf`]: text("%PDF-1.7", 200, "application/pdf"),
    [`${SITE}/notes.txt`]: text("line 1\r\nline 2\n"),
  });
  await assert.rejects(readPage(parsePageTarget(`${SITE}/go`), fetcher(f)), (e) => e.status === 451 && e.body.url === `${SITE}/members/area`);
  await assert.rejects(readPage(parsePageTarget(`${SITE}/missing`), fetcher(f)), (e) => e.status === 422 && /HTTP 404/.test(e.body.reason));
  await assert.rejects(readPage(parsePageTarget(`${SITE}/doc.pdf`), fetcher(f)), (e) => e.status === 415 && e.body.content_type === "application/pdf");
  const t = await readPage(parsePageTarget(`${SITE}/notes.txt`), fetcher(f));
  assert.equal(t.markdown, "line 1\nline 2");
  assert.equal(t.content_type, "text/plain");
});

test("readPage: the size cap is reported; an empty JS-only page gets a note", async () => {
  const f = fakeFetch({ [`${SITE}/big`]: html("<p>" + "word ".repeat(450 * 1024) + "</p>"), [`${SITE}/app`]: html(`<body><div id="root"></div><script>render()</script></body>`) });
  const r = await readPage(parsePageTarget(`${SITE}/big`), fetcher(f));
  assert.equal(r.truncated, true);
  assert.match(r.notes[0], /larger than 1 MB/);
  assert.match(r.notes[1], /only the first 100 KB/);
  assert.ok(r.word_count > 1000);
  const a = await readPage(parsePageTarget(`${SITE}/app`), fetcher(f));
  assert.equal(a.markdown, "");
  assert.match(a.notes.join(" "), /JavaScript/);
});

// ---------------------------------------------------------------- /url-meta logic

test("urlMeta: title, description, canonical, favicon, OpenGraph, Twitter, robots meta, security headers, redirects", async () => {
  const page = `<html lang="fr"><head><title> Page  title </title><meta name="description" content="Desc"><meta name="robots" content="noindex, nofollow">
    <meta property="og:title" content="OG T"><meta property="og:image" content="https://cdn.example.com/i.png"><meta name="twitter:card" content="summary_large_image">
    <link rel="icon" href="/favicon.png"><link rel="icon" type="image/svg+xml" href="/icon.svg"><link rel="canonical" href="https://site.example.com/final"></head>
    <body><img src="a.png"><img src="b.png"><p>hi</p></body></html>`;
  const f = fakeFetch({
    [`${SITE}/start`]: new Response(null, { status: 301, headers: { Location: "/final" } }),
    [`${SITE}/final`]: html(page, { "Strict-Transport-Security": "max-age=31536000", "X-Frame-Options": "DENY", "Content-Length": "999", Server: "test" }),
  });
  let t = 1000;
  const r = await urlMeta(parsePageTarget(`${SITE}/start`), fetcher(f), { clock: () => (t += 37) });
  assert.equal(r.http_status, 200);
  assert.equal(r.final_url, `${SITE}/final`);
  assert.deepEqual(r.redirects, [`${SITE}/final`]);
  assert.equal(r.response_ms, 37);
  assert.equal(r.title, "Page title");
  assert.equal(r.description, "Desc");
  assert.equal(r.canonical, "https://site.example.com/final");
  assert.deepEqual(r.favicon, { url: `${SITE}/icon.svg`, source: "link" });
  assert.equal(r.language, "fr");
  assert.equal(r.open_graph.title, "OG T");
  assert.equal(r.twitter.card, "summary_large_image");
  assert.equal(r.robots_meta.noindex, true);
  assert.equal(r.robots_meta.nofollow, true);
  assert.equal(r.security_headers.hsts.present, true);
  assert.equal(r.security_headers.x_frame_options.value, "DENY");
  assert.equal(r.security_headers.csp.present, false);
  assert.equal(r.content_length, 999);
  assert.equal(r.images_count, 2);
  assert.match(r.notes.join(" "), /noindex/);
});

test("urlMeta: error statuses are reported (not refused); a cross-site redirect is reported; default favicon; robots disallow refused", async () => {
  const f = fakeFetch({
    [`${SITE}/gone`]: html("<html><head><title>Gone</title></head></html>", {}, 410),
    [`${SITE}/away`]: new Response(null, { status: 302, headers: { Location: "https://other.example.org/x" } }),
  });
  const g = await urlMeta(parsePageTarget(`${SITE}/gone`), fetcher(f));
  assert.equal(g.http_status, 410);
  assert.equal(g.favicon.source, "default (not checked)");
  assert.match(g.notes.join(" "), /HTTP 410/);
  const a = await urlMeta(parsePageTarget(`${SITE}/away`), fetcher(f));
  assert.match(a.blocked, /another site/);
  const fr = fakeFetch({ [`${SITE}/robots.txt`]: text("User-agent: *\nDisallow: /") });
  await assert.rejects(urlMeta(parsePageTarget(`${SITE}/x`), fetcher(fr)), (e) => e.status === 451);
});

// ---------------------------------------------------------------- /email-check logic

const dohUrl = (name, type) => `${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`;
const TYPE = { MX: 15, TXT: 16, CNAME: 5 };
function dns(records, { servfail = [], nx = [] } = {}) {
  const routes = {};
  const names = new Set([...Object.keys(records).map((k) => k), ...servfail, ...nx]);
  for (const key of names) {
    const [type, name] = key.split(" ");
    let body;
    if (servfail.includes(key)) body = { Status: 2 };
    else if (nx.includes(key)) body = { Status: 3 };
    else body = { Status: 0, Answer: (records[key] || []).map((data) => ({ name, type: TYPE[type], TTL: 300, data: type === "TXT" ? `"${data}"` : data })) };
    routes[dohUrl(name, type)] = Response.json(body);
  }
  return (url, init) => {
    const r = routes[url];
    if (r) return Promise.resolve(r.clone());
    if (url.startsWith(DOH_URL)) return Promise.resolve(Response.json({ Status: 0, Answer: [] }));
    return Promise.resolve(new Response("nope", { status: 404 }));
  };
}
const codes = (r) => r.findings.map((x) => x.code);

test("parseEmailTarget: strict domain syntax", () => {
  assert.deepEqual(parseEmailTarget(" Example.COM. "), { domain: "example.com" });
  assert.deepEqual(parseEmailTarget("xn--bcher-kva.example"), { domain: "xn--bcher-kva.example" });
  for (const bad of ["", "localhost", "a", "exa mple.com", "-bad.com", "bad-.com", "a..b.com", "1.2.3.4", "ex_ample.com", "printer.local", "x.internal", "x." + "a".repeat(64) + ".com", "x.c0m", 42]) {
    assert.ok(parseEmailTarget(bad).error, `should refuse ${bad}`);
  }
});

test("txtData, parseSpf, parseDmarc", () => {
  assert.equal(txtData(`"v=spf1 include:a.example " "-all"`), "v=spf1 include:a.example -all");
  assert.equal(txtData(`"a\\"b\\\\c\\059d"`), 'a"b\\c;d');
  assert.equal(txtData("unquoted"), "unquoted");
  const p = parseSpf("v=spf1 ip4:1.2.3.4 a mx include:_spf.x.example ptr exists:%{i}.x ?all redirect=y.example exp=e.example");
  assert.equal(p.lookups, 6); // a, mx, include, ptr, exists, redirect
  assert.equal(p.all, "?");
  assert.equal(p.ptr, true);
  assert.deepEqual(p.includes, ["_spf.x.example"]);
  assert.equal(p.redirect, "y.example");
  assert.equal(parseSpf("v=spf1 -all").all, "-");
  assert.equal(parseSpf("v=spf1 all").all, "+");
  assert.deepEqual(parseDmarc("v=DMARC1; p=reject; rua=mailto:a@x.example; pct=50"), { v: "DMARC1", p: "reject", rua: "mailto:a@x.example", pct: "50" });
});

test("emailCheck: healthy domain: MX, SPF -all with nested include count, DMARC reject, DKIM found, MTA-STS, TLS-RPT, BIMI", async () => {
  const f = dns({
    "MX good.example": ["20 mx2.good.example.", "10 mx1.good.example."],
    "TXT good.example": ["v=spf1 include:_spf.good.example -all", "google-site-verification=abc"],
    "TXT _spf.good.example": ["v=spf1 include:_n1.good.example include:_n2.good.example ip4:1.1.1.1 -all"],
    "TXT _n1.good.example": ["v=spf1 ip4:2.2.2.2 -all"],
    "TXT _n2.good.example": ["v=spf1 a -all"],
    "TXT _dmarc.good.example": ["v=DMARC1; p=reject; rua=mailto:dmarc@good.example"],
    "TXT google._domainkey.good.example": ["v=DKIM1; k=rsa; p=MIIBIjAN"],
    "TXT selector1._domainkey.good.example": ["v=DKIM1; p="],
    "TXT _mta-sts.good.example": ["v=STSv1; id=20260101"],
    "TXT _smtp._tls.good.example": ["v=TLSRPTv1; rua=mailto:tls@good.example"],
    "TXT default._bimi.good.example": ["v=BIMI1; l=https://good.example/logo.svg"],
  });
  const r = await emailCheck({ domain: "good.example" }, fetcher(f));
  assert.deepEqual(r.mx.records.map((m) => m.host), ["mx1.good.example", "mx2.good.example"]);
  assert.equal(r.spf.all, "-");
  assert.equal(r.spf.lookups, 4); // include + (include + include) + a
  assert.equal(r.dmarc.policy, "reject");
  assert.deepEqual(r.dkim.found, [{ selector: "google", key_type: "rsa", revoked: false }, { selector: "selector1", key_type: "rsa", revoked: true }]);
  assert.equal(r.mta_sts.present, true);
  assert.equal(r.tls_rpt.present, true);
  assert.equal(r.bimi.logo, "https://good.example/logo.svg");
  assert.equal(r.risk, "LOW");
  assert.deepEqual(codes(r), []);
});

test("emailCheck: +all, multiple SPF, over 10 lookups, missing DMARC, p=none, org-domain fallback, null MX, no MX", async () => {
  const plus = await emailCheck({ domain: "a.example" }, fetcher(dns({ "TXT a.example": ["v=spf1 +all"], "TXT _dmarc.a.example": ["v=DMARC1; p=none"] })));
  assert.ok(codes(plus).includes("SPF_PASS_ALL"));
  assert.ok(codes(plus).includes("DMARC_MONITOR_ONLY"));
  assert.ok(codes(plus).includes("NO_MX"));
  assert.equal(plus.risk, "HIGH");
  const multi = await emailCheck({ domain: "b.example" }, fetcher(dns({ "TXT b.example": ["v=spf1 -all", "v=spf1 ~all"] })));
  assert.ok(codes(multi).includes("SPF_MULTIPLE"));
  assert.ok(codes(multi).includes("NO_DMARC"));
  const recs = { "TXT c.example": ["v=spf1 " + Array.from({ length: 6 }, (_, i) => `include:i${i}.c.example`).join(" ") + " -all"] };
  for (let i = 0; i < 6; i++) recs[`TXT i${i}.c.example`] = ["v=spf1 a mx -all"];
  const many = await emailCheck({ domain: "c.example" }, fetcher(dns(recs)));
  assert.equal(many.spf.lookups, 18);
  assert.ok(codes(many).includes("SPF_TOO_MANY_LOOKUPS"));
  const sub = await emailCheck({ domain: "mail.d.example" }, fetcher(dns({ "MX mail.d.example": ["0 ."], "TXT _dmarc.d.example": ["v=DMARC1; p=quarantine; pct=25"] })));
  assert.equal(sub.mx.null_mx, true);
  assert.ok(codes(sub).includes("NULL_MX"));
  assert.equal(sub.dmarc.source_domain, "d.example");
  assert.ok(codes(sub).includes("DMARC_INHERITED"));
  assert.ok(codes(sub).includes("DMARC_PARTIAL"));
  const missingInclude = await emailCheck({ domain: "e.example" }, fetcher(dns({ "TXT e.example": ["v=spf1 include:gone.example -all"] })));
  assert.ok(codes(missingInclude).includes("SPF_BROKEN_INCLUDE"));
});

test("emailCheck: NXDOMAIN is reported (exists:false); SERVFAIL on a core lookup raises LookupUnavailable", async () => {
  const nx = await emailCheck({ domain: "nope.example" }, fetcher(dns({}, { nx: ["MX nope.example", "TXT nope.example"] })));
  assert.equal(nx.exists, false);
  assert.ok(codes(nx).includes("DOMAIN_NOT_FOUND"));
  await assert.rejects(emailCheck({ domain: "sf.example" }, fetcher(dns({}, { servfail: ["MX sf.example"] }))), LookupUnavailable);
});

// ---------------------------------------------------------------- routes

test("unpaid /read, /url-meta, /email-check: 402 on GET, HEAD and POST with each route's own description and Bazaar info", async () => {
  for (const path of ["/read", "/url-meta", "/email-check"]) {
    for (const method of ["GET", "HEAD", "POST"]) {
      const r = await handle(new Request(ORIGIN + path, { method }), {}, { fetch: fakeFetch() });
      assert.equal(r.status, 402, `${method} ${path}`);
      const pr = b64decodeJson(r.headers.get("PAYMENT-REQUIRED"));
      assert.equal(pr.resource.url, ORIGIN + path);
      assert.ok(pr.extensions.bazaar.info.input.queryParams);
      assert.ok(pr.extensions.bazaar.schema);
    }
  }
});

test("paid /read: robots refusal answers 451 and is never settled; a normal page is settled once", async () => {
  const target = "https://news.example.com/story";
  const f = fakeFetch({ "https://news.example.com/robots.txt": text("User-agent: *\nDisallow: /story") });
  const r = await handle(req(`/read?url=${encodeURIComponent(target)}`, { pay: true }), {}, { fetch: f });
  assert.equal(r.status, 451);
  const body = await r.json();
  assert.equal(body.allowed, false);
  assert.equal(body.charged, false);
  assert.equal(verifies(f), 1);
  assert.equal(settles(f), 0);
  const f2 = fakeFetch({ [target]: html("<html><head><title>Story</title></head><body><article><p>Hello there.</p></article></body></html>") });
  const ok = await handle(req(`/read?url=${encodeURIComponent(target)}`, { pay: true }), {}, { fetch: f2 });
  assert.equal(ok.status, 200);
  const j = await ok.json();
  assert.equal(j.markdown, "Hello there.");
  assert.equal(settles(f2), 1);
  assert.ok(ok.headers.get("PAYMENT-RESPONSE"));
});

test("paid /url-meta and /email-check work end to end; bad input with payment is 400 and the facilitator is never called", async () => {
  const f = fakeFetch({ "https://www.example.org/": html("<html><head><title>Ex</title></head></html>") });
  const m = await handle(req("/url-meta", { method: "POST", body: { url: "https://www.example.org/" }, pay: true }), {}, { fetch: f });
  assert.equal(m.status, 200);
  assert.equal((await m.json()).title, "Ex");
  const dnsFetch = dns({ "TXT ok.example": ["v=spf1 -all"], "TXT _dmarc.ok.example": ["v=DMARC1; p=reject; rua=mailto:x@ok.example"] });
  const calls = [];
  const fe = async (url, init) => {
    calls.push(url);
    if (url.endsWith("/verify")) return Response.json({ isValid: true });
    if (url.endsWith("/settle")) return Response.json({ success: true, transaction: "0x" + "cd".repeat(32), network: "eip155:8453" });
    return dnsFetch(url, init);
  };
  const e = await handle(req("/email-check?domain=ok.example", { pay: true }), {}, { fetch: fe });
  assert.equal(e.status, 200);
  assert.equal((await e.json()).spf.all, "-");
  assert.ok(calls.some((u) => u.endsWith("/settle")));
  for (const [path, why] of [["/read?url=http%3A%2F%2Fx.example%2F", "http"], ["/url-meta?url=https%3A%2F%2F127.0.0.1%2F", "ip"], ["/email-check?domain=localhost", "localhost"], ["/email-check?domain=bad_domain.com", "underscore"]]) {
    const fb = fakeFetch();
    const r = await handle(req(path, { pay: true }), {}, { fetch: fb });
    assert.equal(r.status, 400, why);
    assert.equal(fb.calls.length, 0, `no outbound call for ${why}`);
  }
});

test("a SERVFAIL on a core DNS lookup is a 503 and never settled", async () => {
  const dnsFetch = dns({}, { servfail: ["MX sf.example"] });
  const calls = [];
  const fe = async (url, init) => {
    calls.push(url);
    if (url.endsWith("/verify")) return Response.json({ isValid: true });
    if (url.endsWith("/settle")) return Response.json({ success: true });
    return dnsFetch(url, init);
  };
  const r = await handle(req("/email-check?domain=sf.example", { pay: true }), {}, { fetch: fe });
  assert.equal(r.status, 503);
  assert.ok(!calls.some((u) => u.endsWith("/settle")));
});

test("openapi and llms.txt describe /read, /url-meta and /email-check with prices and refusal codes", async () => {
  const spec = openapi({ ...DEFAULTS, amount: "10000" }, ORIGIN);
  for (const p of ["/read", "/url-meta", "/email-check"]) {
    assert.equal(spec.paths[p].get["x-payment-info"].price.amount, "0.01", p);
    assert.ok(spec.paths[p].post, p);
  }
  assert.ok(spec.paths["/read"].get.responses["451"]);
  assert.ok(spec.paths["/read"].get.responses["415"]);
  const llms = await (await handle(new Request(ORIGIN + "/llms.txt"), {}, {})).text();
  for (const p of ["GET /read", "GET /url-meta", "GET /email-check"]) assert.ok(llms.includes(p), p);
  assert.match(llms, /joi-reader/);
});
