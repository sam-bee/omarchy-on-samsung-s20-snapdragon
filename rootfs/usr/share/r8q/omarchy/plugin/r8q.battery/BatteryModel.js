// Pure battery telemetry presentation and alert policy. It has no hardware or
// power-management side effects.
var LOW_THRESHOLD = 10
var CRITICAL_THRESHOLD = 5
var LOW_CLEAR_THRESHOLD = 15
var CRITICAL_CLEAR_THRESHOLD = 10

function numeric(value) {
  if (typeof value !== "number" && typeof value !== "string") return null
  if (value === null || value === undefined || typeof value === "boolean") return null
  if (typeof value === "string") {
    var trimmed = value.trim()
    if (trimmed === "" || !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(trimmed)) return null
    value = trimmed
  }
  var number = Number(value)
  return isFinite(number) ? number : null
}

function capacityPercent(sample) {
  var fuel = sample && sample.fuel ? sample.fuel : {}
  var value = numeric(fuel.capacity_percent)
  if (value === null || value < 0 || value > 100 || Math.round(value) !== value) return -1
  if (fuel.present !== true) return -1
  return value
}

function netCurrentUa(sample) {
  var value = numeric(sample && sample.net_current_ua)
  if (value !== null) return value
  var fuel = sample && sample.fuel ? sample.fuel : {}
  value = numeric(fuel.current_now_ua)
  if (value !== null) return value
  return numeric(fuel.current_avg_ua)
}

function sourceConnected(sample) {
  return sample && sample.source && sample.source.connected === true
}

function batteryLoad(sample) {
  var current = netCurrentUa(sample)
  // The pinned gauge's negative current sign is the load/discharge evidence.
  return current !== null && current < 0
}

function alertEligible(sample) {
  // Capacity is the warning evidence. Current/source state only decorates the
  // bar: transient sign changes must not re-arm a delivered warning.
  return capacityPercent(sample) >= 0
}

function nextAlertBand(previousBand, level, eligible) {
  var previous = previousBand === "critical" || previousBand === "low" ? previousBand : "normal"
  // A missing capacity sample cannot prove recovery. Preserve the delivered
  // band until a credible capacity crosses its clear threshold.
  if (!eligible || level < 0) return previous

  if (previous === "critical") {
    if (level <= CRITICAL_CLEAR_THRESHOLD) return "critical"
    return level <= LOW_CLEAR_THRESHOLD ? "low" : "normal"
  }
  if (previous === "low") {
    if (level <= CRITICAL_THRESHOLD) return "critical"
    return level <= LOW_CLEAR_THRESHOLD ? "low" : "normal"
  }
  if (level <= CRITICAL_THRESHOLD) return "critical"
  if (level <= LOW_THRESHOLD) return "low"
  return "normal"
}

function alertSeverity(band) {
  if (band === "critical") return 2
  if (band === "low") return 1
  return 0
}

function evaluateAlert(previousBand, sample) {
  var level = capacityPercent(sample)
  var eligible = alertEligible(sample)
  var band = nextAlertBand(previousBand, level, eligible)
  return {
    band: band,
    eligible: eligible,
    notify: alertSeverity(band) > alertSeverity(previousBand),
    level: level
  }
}

function barText(sample) {
  var level = capacityPercent(sample)
  if (level < 0) return "BAT --"
  var current = netCurrentUa(sample)
  var suffix = String(level) + "%"
  if (sourceConnected(sample)) {
    if (current === null) return "USB? " + suffix
    if (current < 0) return "USB↓ " + suffix
    if (current > 0) return "USB↑ " + suffix
    return "USB " + suffix
  }
  // A missing/unknown source is never rendered as charging. A negative gauge
  // current still identifies a battery load even when the charger says so.
  if (current !== null && current < 0) return "BAT↓ " + suffix
  return "BAT? " + suffix
}

if (typeof module !== "undefined") {
  module.exports = {
    LOW_THRESHOLD: LOW_THRESHOLD,
    CRITICAL_THRESHOLD: CRITICAL_THRESHOLD,
    LOW_CLEAR_THRESHOLD: LOW_CLEAR_THRESHOLD,
    CRITICAL_CLEAR_THRESHOLD: CRITICAL_CLEAR_THRESHOLD,
    capacityPercent: capacityPercent,
    netCurrentUa: netCurrentUa,
    sourceConnected: sourceConnected,
    batteryLoad: batteryLoad,
    alertEligible: alertEligible,
    nextAlertBand: nextAlertBand,
    alertSeverity: alertSeverity,
    evaluateAlert: evaluateAlert,
    barText: barText
  }
}
