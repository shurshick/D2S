"use strict";
const assert = require("node:assert/strict");
const ui = require("../internal/web/assets/panel.js");
class Node {
  constructor(doc) { this.ownerDocument = doc; this.children = []; this.value = ""; }
  set textContent(value) { this.value = String(value); this.children = []; }
  get textContent() { return this.value + this.children.map(x => x.textContent).join(""); }
  appendChild(value) { this.children.push(value); return value; }
  replaceChildren(...values) { this.children = values; this.value = ""; }
  querySelectorAll(selector) {
    return this.children.flatMap(x => [
      ...((x.className || "").split(" ").includes(selector.slice(1)) ? [x] : []),
      ...x.querySelectorAll(selector)
    ]);
  }
}
const doc = { createElement: () => new Node(doc), createTextNode(value) {
  const node = new Node(doc); node.textContent = value; return node;
} };
const node = new Node(doc), app = { doc, serverNow: () => Date.now() };
const queued = [{ target: "queued.example", transport: 6, family: 4, since: new Date().toISOString() }];
const memory = { limit: 1, active: 1, queued: 24, free_pct: 97, mem_avail_mb: 44, limited_by: "память" };
ui.App.prototype.updateQueue.call(app, node, queued, memory);
assert.match(node.textContent, /память/);
assert.match(node.textContent, /44 МБ/);
assert.doesNotMatch(node.textContent, /позволяет свободный процессор/);
const rowBefore = node.children;
ui.App.prototype.updateQueue.call(app, node, queued, { ...memory, limited_by: "процессор", free_pct: 12 });
assert.notEqual(node.children, rowBefore, "a changed limiter must update an otherwise unchanged queue");
assert.match(node.textContent, /процессор/);
assert.doesNotMatch(node.textContent, /44 МБ/);
ui.App.prototype.updateQueue.call(app, node, queued, { ...memory, limited_by: "conntrack", conntrack_pct: 63 });
assert.match(node.textContent, /таблица соединений/);
assert.match(node.textContent, /63%/);
ui.App.prototype.updateQueue.call(app, node, queued, { ...memory, limited_by: null });
assert.doesNotMatch(node.textContent, /ограничена: память|ограничена: процессор/);
const view = ui.slotsView(memory);
assert.match(view.short, /память/);
assert.match(view.note, /44 МБ/);
const queuedModel = ui.model({ snapshot: { engine_running: true, live_fresh: true },
  knowledge: { linked: true, searches: [{ target: "queued.example", phase: "в очереди" }] } });
assert.match(queuedModel.lede, /подозрение/);
assert.doesNotMatch(queuedModel.lede, /подтвердил блокировку/);
console.log("Queue reason: memory despite idle CPU, live reason changes, conntrack and missing limiter PASS");
