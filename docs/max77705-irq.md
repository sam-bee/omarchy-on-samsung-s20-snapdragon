# MAX77705 interrupt diagnosis

The SM-G7810 charger startup trials on 2026-10-10 exposed an electrical
configuration mismatch in the PM8150L GPIO11 interrupt input. The device tree
used no pull and VIN selector 0. Samsung's stock `chg_int_default` uses a
pull-up and VIN selector 1, with the same pin, normal function, input direction
and level-low interrupt polarity. The corrected source matches those two
stock settings. The voltage rail behind selector 1 has not been identified.

The stock reference is
`BeneficialCode/android_kernel_samsung_smg7810`, commit
`efbb7d3b9d0c36bd86bd098a9f0c9fc7cc6b2488`,
`arch/arm64/boot/dts/samsung/r8q/kona-sec-r8q-chn-overlay-r00.dts`,
lines 1172–1180. Other retained board-revision overlays agree. The decompiled
stock r8q DT independently places that pin state in the SE0 I2C parent's
default and sleep states.

The phone's PMIC ID/revision is `0x15/0x02`: Samsung calls it MD15 PASS2 and
maps it to logical `MAX77705_PASS5` (5). The mainline acceptance patch uses
numeric revision 2; this does not establish equivalence with every downstream
branch named `MAX77705_PASS2` (2).

## Before correction

Two automatic battery-startup boots reached 100001 parent IRQ deliveries and
the kernel disabled IRQ215. The flood preceded the SE0 I2C timeouts. A later
three-second passive regmap trace recorded 2377 successful, uncached
`INTSRC(0x22)=0` reads while GPIO11 stayed low with VIN selector 0 and no pull.
The generic regmap handler consequently returned IRQ_NONE on each delivery.

The earlier manual charging run did not record IRQ counters or GPIO state.
It establishes usable polling telemetry and charger operation for that run,
but cannot establish an interrupt acceptance pass. A blind IRQ_HANDLED return
would conceal the unhandled count while leaving a low-level interrupt flood.

## Temporary runtime trial

On the existing RTC2 boot, a reviewed diagnostic module changed only the two
pin-state properties in the live device tree before the original battery
modules bound. It did not change the driver, IRQ polarity, masks, current
limits, or persistent boot image. Its OF property storage remains alive until
ordinary reboot; the diagnostic cannot be unloaded normally.

At 15:25 UTC the existing guarded battery helper loaded fuel gauge, MFD and
charger while the desktop was briefly stopped. The desktop then restarted.
GPIO11 became high with VIN selector 1 and a 30-uA pull-up. The eight-second
passive trace recorded one `INTSRC=0x01` event, followed by the unmodified
mainline regmap IRQ handler's ACK and a charger CHGIN nested IRQ. This replaces
the earlier zero-source flood with an identified, handled charger event.

The completed monitor contains 25 samples over 361.59 seconds. The parent IRQ
total stayed at one, with no unhandled event or last-unhandled timestamp. The
kernel journal contains no IRQ disable, failed IRQ-status read or SE0 timeout
during the trial. GPIO11 remained high at the final check. The desktop, USB
route, USB SSH and Wi-Fi SSH worked, and protected payload hashes passed.
This validates the stock setting pair for this bounded runtime trial; it does
not isolate the contribution of pull-up versus VIN selector or establish
behavior during a fresh boot.

Temperature stayed at 24 C and both current limits stayed at 500000 uA.
Mean net battery current was +32112 uA, with 23 positive and two negative
samples; charge rose from 2932000 to 2935000 uAh. This idle desktop profile
made a small net gain and does not establish headroom for arbitrary workloads.

## Persistent correction and automatic startup acceptance

The source correction was included in the persistent audio DTB deployed on
2026-10-10, SHA-256
`d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca`.
It is no longer a temporary property overlay. The kernel EFI payload remains
`50631087ad9b22b8f009b98e9279c1c65d27e4f26c456fe6ce10f29854aaa2bf`.

On 2026-10-11 the corrected persistent configuration passed a guarded manual
bind and two fresh automatic battery-startup boots, `83cb3e73…` and
`822d6a6d…`. Each automatic monitor contains 25 samples over 359.99 seconds.
Parent, charger, CHGIN and AICL IRQ totals remain zero, with zero unhandled
counters and no IRQ disable or MAX/SE0 fault in either full boot journal.
No cable edge was required during these startup trials; a quiet interrupt
line is therefore expected. GPIO11 stays high with VIN 1 and the pull-up.
Desktop, touch, audio, Wi-Fi SSH and USB SSH passed after both starts.

Both limits remain 500000 uA, temperature remains 24 C, and mean sampled net
current is +13162 / +21712 uA. Gauge charge rises by 5000 uAh in each run.
This establishes modest net charging in the tested desktop profile, not
headroom for arbitrary workloads. Battery autoload is now enabled. The
IRQ-less gauge and unused generic MFD child warnings remain recorded as
known limitations, separately from charger faults. Standalone startup,
cable edges, suspend and USB-C negotiation are separate acceptance gates.

The corrected wall-power startup also passes a 25-sample, 359.98-second
capture on boot `668d5aac…`: stable 500000-uA readbacks, zero unhandled
interrupts, no MAX/SE0 faults in the full 770-line boot journal, and charge
3156000 -> 3162000 uAh. Parent/charger/AICL each remain at two handled startup
events; CHGIN remains zero. A laptop-to-wall cable transition earlier recorded
two handled CHGIN events without faults. Wall firmware inherited higher
current settings, so the standalone helper now lowers them through the bound
charger driver to the reviewed 500 mA cap; see the desktop document for its
pinned input-encoding compatibility. Battery-only and post-bind host insertion
are still separate physical gates.

Raw investigation and acceptance evidence is retained under ignored
`out/max77705-investigation-20261010/` and
`out/charger-standalone-20261011/`; the project log records the operational
handoff, independent analyses and payload hashes.
