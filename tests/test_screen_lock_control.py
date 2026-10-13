import importlib.machinery
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'rootfs/usr/local/bin/r8q-screen-lock'
loader = importlib.machinery.SourceFileLoader('screen_lock_control', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
control = importlib.util.module_from_spec(spec)
loader.exec_module(control)


class ScreenLockControlTests(unittest.TestCase):
    def test_optimistic_request_does_not_count_as_secure(self):
        for state in ({'requested': True}, {'requested': True, 'sessionLocked': True, 'secure': False},
                      {'requested': False, 'sessionLocked': True, 'secure': True}):
            self.assertFalse(control.secure(state))

    def test_waits_for_compositor_acknowledgement(self):
        states = [{'requested': True, 'sessionLocked': True, 'secure': False},
                  {'requested': True, 'sessionLocked': True, 'secure': True}]
        with patch.object(control, 'status', side_effect=states), patch.object(control, 'command') as call, patch.object(control.time, 'sleep'):
            control.wait_secure()
            call.assert_called_once_with(['/usr/bin/omarchy-shell', 'lock', 'lock'])

    def test_unconfirmed_lock_times_out_without_dpms(self):
        with patch.object(control.time, 'monotonic', side_effect=[0, 0, 13]), \
             patch.object(control.time, 'sleep'), patch.object(control, 'status', return_value={'secure': False}), \
             patch.object(control, 'command') as call, patch.object(control, 'dpms') as dpms:
            with self.assertRaisesRegex(RuntimeError, 'secure lock'):
                control.wait_secure()
            dpms.assert_not_called()
            call.assert_called_once_with(['/usr/bin/omarchy-shell', 'lock', 'lock'])


if __name__ == '__main__':
    unittest.main()
