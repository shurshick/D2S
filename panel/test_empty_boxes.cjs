"use strict";
const assert = require("node:assert/strict");
const ui = require("../internal/web/assets/panel.js");
const empty = { id: "empty", bindings: [], plans: [{ id: "saved-plan" }] };
const named = { id: "named", bindings: [{ target: "site.example" }], plans: [] };
const address = { id: "address", bindings: [{ kind: "addr", target: "192.0.2.7:443" }], plans: [] };
const unknown = { id: "unavailable", plans: [{ id: "plan" }] };
const boxes = [empty, named, address, unknown];
const m = ui.model({ snapshot: { engine_running: true, catalog_available: true }, knowledge: { linked: true, boxes } });
assert.deepEqual(m.boxes.map(b => b.id), ["named", "address", "unavailable"],
  "explicitly empty boxes must not appear; missing data is not an empty box");
assert.equal(boxes.length, 4, "display filtering must not delete catalog records");
assert.equal(empty.plans.length, 1, "unbound saved plans must remain untouched");
const onlyEmpty = ui.model({ snapshot: { engine_running: true }, knowledge: { boxes: [empty] } });
assert.equal(onlyEmpty.boxes.length, 0);
assert.equal(onlyEmpty.hasUnboundBoxes, true);
assert.equal(m.hasUnboundBoxes, true);
assert.equal(ui.model({ knowledge: { boxes: [named, address] } }).hasUnboundBoxes, false);
assert.deepEqual(ui.model({ knowledge: { boxes: [{ id: "null", bindings: null }] } }).boxes.map(b => b.id), ["null"],
  "null/missing binding data must remain distinguishable from an explicit empty array");
console.log("Empty boxes: hidden without data deletion; named/IP targets and unknown data retained");
