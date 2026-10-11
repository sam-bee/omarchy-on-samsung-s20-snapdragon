#!/usr/bin/env node
"use strict"
const assert = require("assert")
const model = require("../../rootfs/usr/share/r8q/omarchy/plugin/r8q.battery/BatteryModel.js")

function sample(percent, current, source = null, status = "Unknown") {
  return {
    schema: "r8q-battery-telemetry/v1",
    fuel: { present: true, capacity_percent: percent, status, current_now_ua: current, credible: true },
    source: { connected: source, status: source ? "Charging" : "Unknown", health: "Good" },
    net_current_ua: current,
    battery_load: current !== null && current < 0
  }
}

assert.strictEqual(model.capacityPercent(sample(73, -20000)), 73)
assert.strictEqual(model.capacityPercent(sample(null, -20000)), -1)
assert.strictEqual(model.capacityPercent({ fuel: { present: true, capacity_percent: "" } }), -1)
assert.strictEqual(model.capacityPercent(sample(101, -20000)), -1)
assert.strictEqual(model.capacityPercent({ fuel: { present: false, capacity_percent: 9 } }), -1)
assert.strictEqual(model.netCurrentUa({ fuel: { current_now_ua: null, current_avg_ua: -2000 } }), -2000)
assert.strictEqual(model.netCurrentUa({ fuel: { current_now_ua: "", current_avg_ua: null } }), null)
assert.strictEqual(model.alertEligible(sample(9, -20000, true)), true)
assert.strictEqual(model.alertEligible(sample(9, 20000, true)), true)
assert.strictEqual(model.alertEligible(sample(9, -20000, true, "Unknown")), true)
assert.strictEqual(model.barText(sample(73, -20000, true)), "USB↓ 73%")
assert.strictEqual(model.barText(sample(73, -20000, false)), "BAT↓ 73%")
assert.strictEqual(model.barText(sample(73, 20000, null, "Charging")), "BAT? 73%")
assert.strictEqual(model.barText(sample(73, 0, true)), "USB 73%")
assert.strictEqual(model.barText({}), "BAT --")

let result = model.evaluateAlert("normal", sample(9, -20000, true, "Unknown"))
assert.deepStrictEqual({ band: result.band, notify: result.notify }, { band: "low", notify: true })
assert.strictEqual(model.evaluateAlert("low", sample(9, -1000, true)).notify, false)
assert.strictEqual(model.evaluateAlert("low", sample(14, -1000, true)).band, "low")
assert.strictEqual(model.evaluateAlert("low", sample(16, -1000, true)).band, "normal")
assert.strictEqual(model.evaluateAlert("normal", sample(5, -1000, true)).band, "critical")
assert.strictEqual(model.evaluateAlert("critical", sample(9, -1000, true)).band, "critical")
assert.strictEqual(model.evaluateAlert("critical", sample(11, -1000, true)).band, "low")
assert.strictEqual(model.evaluateAlert("critical", sample(11, -1000, true)).notify, false)
assert.strictEqual(model.evaluateAlert("low", sample(5, -1000, true)).notify, true)
assert.strictEqual(model.evaluateAlert("low", sample(9, 20000, true)).band, "low")
assert.strictEqual(model.evaluateAlert("low", sample(9, null, null)).band, "low")
assert.strictEqual(model.evaluateAlert("low", {}).band, "low")
assert.strictEqual(model.evaluateAlert("low", sample(16, 0, true)).band, "normal")
assert.strictEqual(model.evaluateAlert("normal", sample(9, 20000, true)).notify, true)

console.log("battery model telemetry fixtures: ok")
