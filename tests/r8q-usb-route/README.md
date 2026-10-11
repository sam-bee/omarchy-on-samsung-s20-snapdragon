# Production USB route helper fixtures

`test_r8q_usb_route.py` runs the production helper from
`rootfs/usr/local/sbin/r8q-usb-route-ensure.sh` against a synthetic sysfs/proc
tree and a stub `i2ctransfer`. It does not access a phone, network, or device
node. The pinned source repository/commit and all source hash fields are
always checked. If the ignored exact-source bundle exists under `out/`, the
test additionally verifies its manifest, verification receipt, and seven
source files; otherwise it reports that stronger check as unavailable and
continues with the self-contained protocol fixtures.

The deployed helper requires `/etc/r8q-usb-route.env` to be a regular file
containing exactly these four assignments (comments and blank lines are
allowed), plus the five wrapper metadata assignments below:

```text
EXPECTED_KERNEL=<deployment kernel release>
EXPECTED_MACHINE_ID=<deployment machine-id>
EXPECTED_ROOT_UUID=<deployment root filesystem UUID>
EXPECTED_BOOT_SHA256=<deployment clean BOOT SHA-256>
EXPECTED_VERMAGIC='<module vermagic with spaces quoted>'
EXPECTED_GPI_SHA256=<deployment gpi.ko SHA-256>
EXPECTED_GENI_SHA256=<deployment i2c-qcom-geni.ko SHA-256>
EXPECTED_HELPER_SHA256=<deployed helper SHA-256>
EXPECTED_PROTOCOL_SHA256=<deployed protocol-binding.env SHA-256>
```

The helper parses this file as data and never sources or evaluates it. Unknown
variables, duplicates, empty values, malformed UUIDs, and malformed hashes fail
before the per-boot state directory is reserved. The reviewed
source protocol is fixed at
`/usr/local/lib/r8q-usb-route/protocol-binding.env`. A wrapper must set
`R8Q_USB_ROUTE_HARDWARE_MODE=1` explicitly after its own identity and module
guards pass. The helper stores one attempt and its raw transaction receipt per
boot under `/var/lib/r8q-usb-route/<boot-id>/`; there is no global once marker.

The standalone preparation unit sets `R8Q_USB_ROUTE_OPTIONAL_NOHOST=1`.
Fixtures cover canonical unplugged/no-VBUS and wall-DCP deferrals, requiring
zero UIC reads and zero mailbox writes; inconsistent, unsafe or unknown BC/CC
states fail. The SDP host transaction keeps its existing source-bound guards.
`test_witness.sh` feeds real helper-generated append-only receipts to the
read-only legacy witness and rejects deferred, missing and malformed receipts.

Run offline checks from the repository root:

```sh
/bin/sh -n rootfs/usr/local/sbin/r8q-usb-route-ensure.sh
python3 -B tests/r8q-usb-route/test_r8q_usb_route.py
sh tests/r8q-usb-route/test_startup.sh
sh tests/r8q-usb-route/test_witness.sh
python3 -B tests/test_standalone_units.py
```
