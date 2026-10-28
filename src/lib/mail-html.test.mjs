import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMailDocument, sanitizeMailHtml } from './mail-html.ts';

test('script/noscript 连内容一起删掉，style 保留', () => {
  const output = sanitizeMailHtml('<style>.a{color:red}</style><script>alert(1)</script><noscript>fallback</noscript><p>正文</p>');
  assert.ok(!output.toLowerCase().includes('script'));
  assert.ok(!output.includes('alert(1)'));
  assert.ok(output.includes('.a{color:red}'));
  assert.ok(output.includes('<p>正文</p>'));
});

test('on* 事件属性全部剥离，其余属性保留', () => {
  const output = sanitizeMailHtml(
    '<img src="data:image/png;base64,AAAA" onerror="alert(1)" ONLOAD=alert(2)><div onclick="x" onmouseover="y" class="body">hi</div>',
  );
  assert.ok(!/on[a-z]+\s*=/i.test(output));
  assert.ok(output.includes('class="body"'));
  assert.ok(output.includes('src="data:image/png;base64,AAAA"'));
  assert.ok(output.includes('hi'));
});

test('javascript/vbscript 与混淆写法都会被剥掉', () => {
  const output = sanitizeMailHtml(
    '<a href="javascript:alert(1)">a</a><a href=" JaVa\tScRiPt:alert(1)">b</a><a href="&#106;avascript:alert(1)">c</a><a href="vbscript:msgbox(1)">d</a>',
  );
  assert.ok(!/javascript/i.test(output));
  assert.ok(!/vbscript/i.test(output));
  assert.ok(!output.includes('href'));
});

test('正常链接补 target 与 rel，并覆盖已有值', () => {
  const output = sanitizeMailHtml('<a href="https://example.com/a?b=1" target="_self" rel="opener">链接</a>');
  assert.ok(output.includes('target="_blank"'));
  assert.ok(output.includes('rel="noopener noreferrer"'));
  assert.ok(!output.includes('_self'));
  assert.equal(output.match(/target=/g)?.length, 1);
  assert.equal(output.match(/href=/g)?.length, 1);
});

test('iframe/object/embed/link/base/form/meta 被移除', () => {
  const output = sanitizeMailHtml(
    '<iframe src="https://evil.test"></iframe><object data="x"><param name="a" value="b"></object>' +
      '<embed src="x"><link rel="stylesheet" href="x"><base href="https://evil.test/"><meta http-equiv="refresh" content="0">' +
      '<form action="x"><input value="pwd"><button>go</button></form><p>ok</p>',
  );
  for (const tag of ['iframe', 'object', 'param', 'embed', 'link', 'base', 'meta', 'form', 'input', 'button']) {
    assert.ok(!output.toLowerCase().includes(`<${tag}`), tag);
  }
  assert.ok(output.includes('<p>ok</p>'));
});

test('外链样式与 data:text/html 被剥掉，data 图片保留', () => {
  const output = sanitizeMailHtml(
    '<style>@import url("https://evil.test/a.css");.x{color:red}</style>' +
      '<a href="data:text/html,<b>x</b>">a</a><img src="data:text/html;base64,AAAA"><img src="data:image/gif;base64,BBB">',
  );
  assert.ok(!output.includes('@import'));
  assert.ok(output.includes('.x{color:red}'));
  assert.ok(!/data:text\/html/i.test(output));
  assert.ok(output.includes('data:image/gif;base64,BBB'));
});

test('style 属性里的 expression/javascript 会被丢弃', () => {
  const output = sanitizeMailHtml('<p style="color:red">ok</p><p style="width:expression(alert(1))">x</p><p style="background:url(javascript:alert(1))">y</p>');
  assert.ok(output.includes('style="color:red"'));
  assert.ok(!output.toLowerCase().includes('expression'));
  assert.ok(!/javascript/i.test(output));
});

test('srcset 里的危险地址会让整块属性被丢弃', () => {
  const output = sanitizeMailHtml('<img srcset="https://ok.test/a.png 1x, javascript:alert(1) 2x"><img srcset="data:image/png;base64,AAA 1x">');
  assert.ok(!/javascript/i.test(output));
  assert.ok(output.includes('data:image/png;base64,AAA 1x'));
});

test('buildMailDocument 输出带 CSP/referrer/charset 的完整文档', () => {
  const doc = buildMailDocument('<p>hello</p>');
  assert.ok(doc.startsWith('<!DOCTYPE html>'));
  assert.ok(doc.includes('<meta charset="utf-8">'));
  assert.ok(doc.includes('name="referrer" content="no-referrer"'));
  assert.ok(doc.includes('Content-Security-Policy'));
  assert.ok(doc.includes("default-src 'none'"));
  assert.ok(doc.includes('img-src data:'));
  assert.ok(doc.includes("style-src 'unsafe-inline'"));
  assert.ok(doc.includes('<p>hello</p>'));
  assert.equal(doc.match(/<body>/g)?.length, 1);
});

test('文档底色为白色、body 有内边距，正文不贴边', () => {
  const doc = buildMailDocument('<p>hello</p>');
  assert.ok(doc.includes('background: #ffffff'));
  assert.ok(!doc.includes('background: transparent'));
  assert.ok(doc.includes('padding: 14px 16px'));
});

test('没有可显示内容时返回空串，好让调用方退回纯文本', () => {
  assert.equal(buildMailDocument(''), '');
  assert.equal(buildMailDocument('   '), '');
  assert.equal(buildMailDocument('<html><body>  \n </body></html>'), '');
  assert.equal(buildMailDocument('<html><head><style>.a{color:red}</style></head><body></body></html>'), '');
});

test('纯图片邮件（正文文本为空）仍然产出文档', () => {
  const doc = buildMailDocument('<p><img src="data:image/png;base64,AAAA" alt="海报"></p>');
  assert.ok(doc.startsWith('<!DOCTYPE html>'));
  assert.ok(doc.includes('data:image/png;base64,AAAA'));
});

test('完整文档会抽出 body 内容并合并 head 里的 style', () => {
  const doc = buildMailDocument(
    '<html><head><title>标题</title><style>.m{color:#333}</style></head><body class="x"><div>内容</div></body></html>',
  );
  assert.ok(doc.includes('<div>内容</div>'));
  assert.ok(doc.includes('.m{color:#333}'));
  assert.ok(!doc.includes('<title>'));
  assert.equal(doc.match(/<html/g)?.length, 1);
  assert.equal(doc.match(/<body/g)?.length, 1);
  assert.equal(doc.match(/\.m\{color:#333\}/g)?.length, 1);
});

test('只有 html/head 没有 body 时也不产生重复样式', () => {
  const doc = buildMailDocument('<html><head><style>.z{color:red}</style></head><p>只有正文</p></html>');
  assert.ok(doc.includes('<p>只有正文</p>'));
  assert.equal(doc.match(/\.z\{color:red\}/g)?.length, 1);
});

test('畸形输入不抛异常', () => {
  const inputs = [
    '',
    '   ',
    '<div onclick="x"',
    '<script>alert(1)',
    '<img src=x onerror=alert(1)',
    '<<<>>>',
    '<a href="javascript:alert(1)',
    '</body></html>',
    '<html><body><p>无闭合',
    '<style>@import url(https://evil.test/a.css);.x{color:red}</style>',
  ];
  for (const input of inputs) {
    assert.doesNotThrow(() => sanitizeMailHtml(input), input);
    assert.doesNotThrow(() => buildMailDocument(input), input);
  }
  assert.equal(sanitizeMailHtml(''), '');
  assert.equal(buildMailDocument(''), '');
});
