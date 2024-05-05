import unittest
from dhcp_capture import capture_dhcp_packets


class TestDHCP(unittest.TestCase):
    def test_capture_dhcp_packets(self):
        # Call the function to capture DHCP packets
        captured_packets = capture_dhcp_packets()

        # Assert that the captured packets are not empty
        self.assertTrue(captured_packets, "No DHCP packets captured")

        # Add more assertions to validate the captured packets if needed

if __name__ == '__main__':
    # Run the test case
    unittest.main()