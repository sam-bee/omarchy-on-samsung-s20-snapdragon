# Phone lock input checks

These Qt Quick tests exercise the production view with synthetic credentials:
digit clicks, backspace/clear, empty submission, masked physical-keyboard
input, clearing before submission, long-password feedback, error reset, and
disabled input during authentication. They invoke no PAM or session locking.

On an ARM test system with the existing Qt runtime, preserve the repository
directory layout and run:

```sh
QT_QUICK_BACKEND=software /usr/lib/qt6/bin/qmltestrunner \
  -platform offscreen -input tests/r8q-lock
```

Passing these tests does not establish real touchscreen acceptance, successful
PAM authentication, compositor session-lock coverage, or lock durability.
The separate preview must still be tried physically before activating a lock.
