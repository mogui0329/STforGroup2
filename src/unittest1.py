import unittest
from ctypes import *
from template import *

# This is used to test `template.h` and `template.c`.
# Author: zhsh.


class TestTemplate(unittest.TestCase):
    """_summary_

    Args:
        unittest (_type_): _description_

    Decription:
        there are some variable name(s), file name(s), buffer content(s) still remained unchanging,
        because the deployment test meets some trouble and ecc is 404 right now.
    """
    def test_handle_exec(self):
        # Create some test data
        ctx = trace_event_raw_sched_process_exec()
        ctx.__data_loc_filename = 0x12345
        pid = 1234
        task = c_void_p()
        comm = create_string_buffer(b"test", TASK_COMM_LEN)
        filename = create_string_buffer(b"/path/to/executable", MAX_FILENAME_LEN)

        # Mock the BPF functions
        bpf_get_current_pid_tgid = lambda: pid << 32
        bpf_get_current_task = lambda: task
        bpf_probe_read_str = lambda dst, size, addr: strncpy(dst, filename.value, size)

        # Call the function being tested
        handle_exec(ctx)

        # Check that the event was added to the ring buffer
        ringbuf = rb.__class__.from_buffer(rb)
        event = ringbuf[0]
        self.assertEqual(event.pid, pid)
        self.assertEqual(event.comm, b"test")
        self.assertEqual(event.filename, b"/path/to/executable")
        self.assertFalse(event.exit_event)

if __name__ == '__main__':
    unittest.main()
