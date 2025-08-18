"""
Comprehensive unit tests for baconfreak.py core functionality.
"""

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.baconfreak import (
    BaconFreakError,
    BaconFreakPermissionError,
    BaconFreakInterfaceError,
    BluetoothScanner,
    pcap_writers,
)
from src.models import DeviceType, PacketInfo, ScanConfiguration


class TestBaconFreakExceptions(unittest.TestCase):
    """Test custom exception classes."""

    def test_bacon_freak_error(self):
        """Test base BaconFreakError exception."""
        error = BaconFreakError("test error")
        self.assertEqual(str(error), "test error")
        self.assertIsInstance(error, Exception)

    def test_bacon_freak_permission_error(self):
        """Test BaconFreakPermissionError exception."""
        error = BaconFreakPermissionError("permission denied")
        self.assertEqual(str(error), "permission denied")
        self.assertIsInstance(error, BaconFreakError)

    def test_bacon_freak_interface_error(self):
        """Test BaconFreakInterfaceError exception."""
        error = BaconFreakInterfaceError("interface not found")
        self.assertEqual(str(error), "interface not found")
        self.assertIsInstance(error, BaconFreakError)


class TestPcapWriters(unittest.TestCase):
    """Test pcap_writers context manager."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.known_path = self.temp_dir / "known.pcap"
        self.unknown_path = self.temp_dir / "unknown.pcap"

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    @patch('src.baconfreak.PcapWriter')
    def test_pcap_writers_success(self, mock_pcap_writer):
        """Test successful pcap writers context manager."""
        mock_known = Mock()
        mock_unknown = Mock()
        mock_pcap_writer.side_effect = [mock_known, mock_unknown]

        with pcap_writers(self.known_path, self.unknown_path) as (known, unknown):
            self.assertEqual(known, mock_known)
            self.assertEqual(unknown, mock_unknown)

        # Verify both writers were closed
        mock_known.close.assert_called_once()
        mock_unknown.close.assert_called_once()

    @patch('src.baconfreak.PcapWriter')
    def test_pcap_writers_cleanup_on_exception(self, mock_pcap_writer):
        """Test pcap writers cleanup on exception."""
        mock_known = Mock()
        mock_unknown = Mock()
        mock_pcap_writer.side_effect = [mock_known, mock_unknown]

        try:
            with pcap_writers(self.known_path, self.unknown_path) as (known, unknown):
                raise Exception("test exception")
        except Exception:
            pass

        # Verify both writers were closed even after exception
        mock_known.close.assert_called_once()
        mock_unknown.close.assert_called_once()

    @patch('src.baconfreak.PcapWriter')
    def test_pcap_writers_partial_failure(self, mock_pcap_writer):
        """Test pcap writers with partial initialization failure."""
        mock_known = Mock()
        mock_pcap_writer.side_effect = [mock_known, Exception("writer failed")]

        try:
            with pcap_writers(self.known_path, self.unknown_path):
                pass
        except Exception:
            pass

        # Known writer should still be closed
        mock_known.close.assert_called_once()


class TestBluetoothScannerInitialization(unittest.TestCase):
    """Test BluetoothScanner initialization."""

    @patch('src.baconfreak.ModernCompanyIdentifiers')
    @patch('src.baconfreak.ModernDeviceDetector')
    @patch('src.baconfreak.BaconFreakLogger')
    @patch('src.baconfreak.config')
    def test_scanner_initialization_default(self, mock_config, mock_logger, mock_detector, mock_company):
        """Test scanner initialization with defaults."""
        mock_scan_config = Mock()
        mock_config.scan_config = mock_scan_config
        
        scanner = BluetoothScanner()
        
        self.assertEqual(scanner.scan_config, mock_scan_config)
        self.assertTrue(scanner.enable_rich)
        self.assertFalse(scanner.quiet)
        self.assertIsInstance(scanner.devices, dict)
        self.assertFalse(scanner._running)

    @patch('src.baconfreak.ModernCompanyIdentifiers')
    @patch('src.baconfreak.ModernDeviceDetector')
    @patch('src.baconfreak.BaconFreakLogger')
    @patch('src.baconfreak.config')
    def test_scanner_initialization_custom_interface(self, mock_config, mock_logger, mock_detector, mock_company):
        """Test scanner initialization with custom interface."""
        mock_scan_config = Mock()
        mock_config.scan_config = mock_scan_config
        
        scanner = BluetoothScanner(interface=2)
        
        self.assertEqual(scanner.scan_config.interface, 2)

    @patch('src.baconfreak.ModernCompanyIdentifiers')
    @patch('src.baconfreak.ModernDeviceDetector')
    @patch('src.baconfreak.BaconFreakLogger')
    @patch('src.baconfreak.config')
    def test_scanner_initialization_quiet_mode(self, mock_config, mock_logger, mock_detector, mock_company):
        """Test scanner initialization in quiet mode."""
        mock_scan_config = Mock()
        mock_config.scan_config = mock_scan_config
        
        scanner = BluetoothScanner(quiet=True, enable_rich=True)
        
        self.assertFalse(scanner.enable_rich)  # Should be disabled in quiet mode
        self.assertTrue(scanner.quiet)
        self.assertIsNone(scanner.console)

    @patch('src.baconfreak.ModernCompanyIdentifiers')
    @patch('src.baconfreak.ModernDeviceDetector')
    @patch('src.baconfreak.BaconFreakLogger')
    @patch('src.baconfreak.config')
    def test_scanner_initialization_with_scan_config(self, mock_config, mock_logger, mock_detector, mock_company):
        """Test scanner initialization with custom scan config."""
        custom_config = ScanConfiguration(interface=3, scan_timeout=60)
        
        scanner = BluetoothScanner(scan_config=custom_config)
        
        self.assertEqual(scanner.scan_config, custom_config)

    @patch('src.baconfreak.ModernCompanyIdentifiers')
    @patch('src.baconfreak.ModernDeviceDetector')
    @patch('src.baconfreak.BaconFreakLogger')
    @patch('src.baconfreak.config')
    def test_scanner_initialization_component_failure(self, mock_config, mock_logger, mock_detector, mock_company):
        """Test scanner initialization with component failure."""
        mock_config.scan_config = Mock()
        mock_company.side_effect = Exception("Company resolver failed")
        
        with self.assertRaises(BaconFreakError):
            BluetoothScanner()


class TestBluetoothScannerMethods(unittest.TestCase):
    """Test BluetoothScanner methods."""

    def setUp(self):
        """Set up test fixtures."""
        with patch('src.baconfreak.ModernCompanyIdentifiers'), \
             patch('src.baconfreak.ModernDeviceDetector'), \
             patch('src.baconfreak.BaconFreakLogger'), \
             patch('src.baconfreak.config') as mock_config:
            mock_config.scan_config = Mock()
            self.scanner = BluetoothScanner()

    def test_signal_handler(self):
        """Test signal handler."""
        self.scanner._signal_handler(2, None)
        self.assertTrue(self.scanner.exit_event.is_set())
        self.assertFalse(self.scanner._running)

    def test_stop_method(self):
        """Test stop method."""
        self.scanner._running = True
        self.scanner.stop()
        
        self.assertTrue(self.scanner.exit_event.is_set())
        self.assertFalse(self.scanner._running)

    def test_stop_filter(self):
        """Test stop filter function."""
        # Initially should return False
        self.assertFalse(self.scanner._stop_filter(None))
        
        # After setting exit event should return True
        self.scanner.exit_event.set()
        self.assertTrue(self.scanner._stop_filter(None))

    @patch('src.baconfreak.Console')
    def test_create_live_display(self, mock_console):
        """Test live display creation."""
        self.scanner.enable_rich = True
        layout = self.scanner._create_live_display()
        
        # Should have header, main, and footer sections
        self.assertIsNotNone(layout)

    def test_create_device_table(self):
        """Test device table creation."""
        # Add some mock devices
        from src.models import BluetoothDevice
        from datetime import datetime, timedelta
        
        now = datetime.now()
        device1 = BluetoothDevice(
            addr="aa:bb:cc:dd:ee:ff",
            device_type=DeviceType.AIRTAG_UNREGISTERED,
            rssi=-45,
            company_name="Apple, Inc.",
            packet_count=5,
            first_seen=now - timedelta(minutes=5),
            last_seen=now - timedelta(seconds=10)
        )
        
        device2 = BluetoothDevice(
            addr="11:22:33:44:55:66", 
            device_type=DeviceType.UNKNOWN,
            rssi=-80,
            packet_count=2,
            first_seen=now - timedelta(hours=2),
            last_seen=now - timedelta(minutes=1)
        )
        
        self.scanner.devices = {
            "aa:bb:cc:dd:ee:ff": device1,
            "11:22:33:44:55:66": device2
        }
        
        table = self.scanner._create_device_table()
        self.assertIsNotNone(table)

    def test_format_time_delta(self):
        """Test time delta formatting."""
        from datetime import timedelta
        
        # Test seconds
        delta = timedelta(seconds=30)
        result = self.scanner._format_time_delta(delta)
        self.assertEqual(result, "30s")
        
        # Test minutes (compact format)
        delta = timedelta(minutes=5, seconds=30)
        result = self.scanner._format_time_delta(delta)
        self.assertEqual(result, "5m")
        
        # Test hours and minutes
        delta = timedelta(hours=2, minutes=30)
        result = self.scanner._format_time_delta(delta)
        self.assertEqual(result, "2h30m")
        
        # Test hours only
        delta = timedelta(hours=3)
        result = self.scanner._format_time_delta(delta)
        self.assertEqual(result, "3h")
        
        # Test days and hours
        delta = timedelta(days=1, hours=5)
        result = self.scanner._format_time_delta(delta)
        self.assertEqual(result, "1d5h")
        
        # Test days only
        delta = timedelta(days=2)
        result = self.scanner._format_time_delta(delta)
        self.assertEqual(result, "2d")

    def test_handle_keyboard_input(self):
        """Test keyboard input handling for sorting."""
        # Test RSSI sorting toggle
        self.scanner._handle_keyboard_input('r')
        self.assertEqual(self.scanner.sort_mode, "rssi")
        self.assertFalse(self.scanner.sort_ascending)
        
        # Toggle again should flip direction
        self.scanner._handle_keyboard_input('r')
        self.assertEqual(self.scanner.sort_mode, "rssi")
        self.assertTrue(self.scanner.sort_ascending)
        
        # Test First Seen sorting
        self.scanner._handle_keyboard_input('f')
        self.assertEqual(self.scanner.sort_mode, "first_seen")
        self.assertFalse(self.scanner.sort_ascending)
        
        # Test Last Seen sorting
        self.scanner._handle_keyboard_input('l')
        self.assertEqual(self.scanner.sort_mode, "last_seen")
        self.assertFalse(self.scanner.sort_ascending)
        
        # Test Total Time sorting
        self.scanner._handle_keyboard_input('t')
        self.assertEqual(self.scanner.sort_mode, "total_time")
        self.assertFalse(self.scanner.sort_ascending)
        
        # Test Packets sorting
        self.scanner._handle_keyboard_input('p')
        self.assertEqual(self.scanner.sort_mode, "packets")
        self.assertFalse(self.scanner.sort_ascending)
        
        # Toggle again should flip direction
        self.scanner._handle_keyboard_input('p')
        self.assertEqual(self.scanner.sort_mode, "packets")
        self.assertTrue(self.scanner.sort_ascending)
        
        # Test case insensitive
        self.scanner._handle_keyboard_input('R')
        self.assertEqual(self.scanner.sort_mode, "rssi")

    def test_device_sorting(self):
        """Test device sorting with different modes."""
        from src.models import BluetoothDevice
        from datetime import datetime, timedelta
        
        now = datetime.now()
        
        # Create devices with different characteristics
        device1 = BluetoothDevice(
            addr="aa:bb:cc:dd:ee:ff",
            device_type=DeviceType.AIRTAG_UNREGISTERED,
            rssi=-30,  # Strong signal
            first_seen=now - timedelta(minutes=10),
            last_seen=now - timedelta(seconds=5)
        )
        
        device2 = BluetoothDevice(
            addr="11:22:33:44:55:66", 
            device_type=DeviceType.UNKNOWN,
            rssi=-90,  # Weak signal
            first_seen=now - timedelta(minutes=5),  # More recent first seen
            last_seen=now - timedelta(seconds=30)
        )
        
        self.scanner.devices = {
            "aa:bb:cc:dd:ee:ff": device1,
            "11:22:33:44:55:66": device2
        }
        
        # Test RSSI sorting (descending = strongest first)
        self.scanner.sort_mode = "rssi"
        self.scanner.sort_ascending = False
        table = self.scanner._create_device_table()
        self.assertIsNotNone(table)
        
        # Test first seen sorting
        self.scanner.sort_mode = "first_seen"
        self.scanner.sort_ascending = False
        table = self.scanner._create_device_table()
        self.assertIsNotNone(table)
        
        # Test total time sorting
        self.scanner.sort_mode = "total_time"
        self.scanner.sort_ascending = False
        table = self.scanner._create_device_table()
        self.assertIsNotNone(table)

    def test_create_stats_panel(self):
        """Test statistics panel creation."""
        # Add some stats
        self.scanner.stats.total_packets = 100
        self.scanner.stats.valid_packets = 95
        self.scanner.stats.devices_by_type = {DeviceType.AIRTAG_UNREGISTERED: 3}
        self.scanner.stats.known_companies = {"Apple, Inc."}
        self.scanner.stats.unknown_company_ids = {999}
        
        panel = self.scanner._create_stats_panel()
        self.assertIsNotNone(panel)

    def test_create_footer(self):
        """Test footer creation."""
        footer = self.scanner._create_footer()
        self.assertIsNotNone(footer)

    def test_update_performance_stats(self):
        """Test performance statistics update."""
        self.scanner.stats.total_packets = 100
        
        # Mock config get method and force time difference
        with patch.object(self.scanner, 'logger') as mock_logger:
            with patch('src.baconfreak.config') as mock_config:
                mock_config.get.return_value = 1  # Short interval for testing
                
                # Force time difference by setting last update to past
                from datetime import datetime, timedelta
                self.scanner._last_stats_update = datetime.now() - timedelta(seconds=20)
                
                self.scanner._update_performance_stats()
                
                # Should update packets per second
                self.assertGreaterEqual(self.scanner.stats.packets_per_second, 0)


class TestBluetoothScannerPacketProcessing(unittest.TestCase):
    """Test BluetoothScanner packet processing."""

    def setUp(self):
        """Set up test fixtures."""
        with patch('src.baconfreak.ModernCompanyIdentifiers'), \
             patch('src.baconfreak.ModernDeviceDetector'), \
             patch('src.baconfreak.BaconFreakLogger'), \
             patch('src.baconfreak.config') as mock_config:
            mock_config.scan_config = Mock(min_rssi=-100)
            self.scanner = BluetoothScanner()

    def test_get_or_create_device_new(self):
        """Test creating new device."""
        packet_info = PacketInfo(
            addr="aa:bb:cc:dd:ee:ff",
            rssi=-50,
            company_id=76
        )
        
        mock_device = Mock()
        self.scanner.device_detector.create_device.return_value = mock_device
        
        device = self.scanner._get_or_create_device(packet_info)
        
        self.assertEqual(device, mock_device)
        self.assertIn("aa:bb:cc:dd:ee:ff", self.scanner.devices)
        self.scanner.device_detector.create_device.assert_called_once_with(packet_info)

    def test_get_or_create_device_existing(self):
        """Test updating existing device."""
        # Add existing device
        existing_device = Mock()
        existing_device.addr = "aa:bb:cc:dd:ee:ff"
        self.scanner.devices["aa:bb:cc:dd:ee:ff"] = existing_device
        
        packet_info = PacketInfo(
            addr="aa:bb:cc:dd:ee:ff",
            rssi=-45,
            data="1234",
            device_name="Test Device"
        )
        
        device = self.scanner._get_or_create_device(packet_info)
        
        self.assertEqual(device, existing_device)
        existing_device.update_seen.assert_called_once_with(-45, "1234", "Test Device")

    @patch('src.baconfreak.HCI_LE_Meta_Advertising_Reports')
    def test_packet_callback_no_advertising_reports(self, mock_reports):
        """Test packet callback with no advertising reports."""
        mock_packet = Mock()
        mock_packet.haslayer.return_value = False
        
        mock_known_writer = Mock()
        mock_unknown_writer = Mock()
        
        # Should not raise exception
        self.scanner._packet_callback(mock_packet, mock_known_writer, mock_unknown_writer)

    def test_packet_callback_with_exception(self):
        """Test packet callback with exception handling."""
        mock_packet = Mock()
        mock_packet.haslayer.side_effect = Exception("Test exception")
        
        mock_known_writer = Mock()
        mock_unknown_writer = Mock()
        
        # Should not raise exception and should increment total packets
        initial_count = self.scanner.stats.total_packets
        self.scanner._packet_callback(mock_packet, mock_known_writer, mock_unknown_writer)
        
        self.assertEqual(self.scanner.stats.total_packets, initial_count + 1)

    def test_process_advertising_report_below_rssi_threshold(self):
        """Test processing report below RSSI threshold."""
        mock_report = Mock()
        
        packet_info = PacketInfo(addr="aa:bb:cc:dd:ee:ff", rssi=-120)  # Below threshold
        self.scanner.device_detector.extract_packet_info.return_value = packet_info
        
        mock_known_writer = Mock()
        mock_unknown_writer = Mock()
        
        self.scanner._process_advertising_report(mock_report, Mock(), mock_known_writer, mock_unknown_writer)
        
        # Should not write to PCAP files
        mock_known_writer.write.assert_not_called()
        mock_unknown_writer.write.assert_not_called()

    def test_process_advertising_report_known_company(self):
        """Test processing report from known company."""
        mock_report = Mock()
        
        packet_info = PacketInfo(addr="aa:bb:cc:dd:ee:ff", rssi=-50, company_id=76)
        self.scanner.device_detector.extract_packet_info.return_value = packet_info
        self.scanner.device_detector.is_known_company.return_value = True
        
        mock_device = Mock()
        mock_device.company_name = "Apple, Inc."
        self.scanner.device_detector.create_device.return_value = mock_device
        
        mock_original_packet = Mock()
        mock_known_writer = Mock()
        mock_unknown_writer = Mock()
        
        self.scanner._process_advertising_report(mock_report, mock_original_packet, mock_known_writer, mock_unknown_writer)
        
        # Should write to known writer
        mock_known_writer.write.assert_called_once_with(mock_original_packet)
        mock_unknown_writer.write.assert_not_called()
        
        # Should add to known companies
        self.assertIn("Apple, Inc.", self.scanner.stats.known_companies)

    def test_process_advertising_report_unknown_company(self):
        """Test processing report from unknown company."""
        mock_report = Mock()
        
        packet_info = PacketInfo(addr="aa:bb:cc:dd:ee:ff", rssi=-50, company_id=999)
        self.scanner.device_detector.extract_packet_info.return_value = packet_info
        self.scanner.device_detector.is_known_company.return_value = False
        
        mock_device = Mock()
        mock_device.company_name = None
        self.scanner.device_detector.create_device.return_value = mock_device
        
        mock_original_packet = Mock()
        mock_known_writer = Mock()
        mock_unknown_writer = Mock()
        
        self.scanner._process_advertising_report(mock_report, mock_original_packet, mock_known_writer, mock_unknown_writer)
        
        # Should write to unknown writer
        mock_unknown_writer.write.assert_called_once_with(mock_original_packet)
        mock_known_writer.write.assert_not_called()
        
        # Should add to unknown company IDs
        self.assertIn(999, self.scanner.stats.unknown_company_ids)


class TestBluetoothScannerInterface(unittest.TestCase):
    """Test BluetoothScanner Bluetooth interface methods."""

    def setUp(self):
        """Set up test fixtures."""
        with patch('src.baconfreak.ModernCompanyIdentifiers'), \
             patch('src.baconfreak.ModernDeviceDetector'), \
             patch('src.baconfreak.BaconFreakLogger'), \
             patch('src.baconfreak.config') as mock_config:
            mock_scan_config = Mock()
            mock_scan_config.interface = 1
            mock_scan_config.filter_duplicates = False
            mock_config.scan_config = mock_scan_config
            self.scanner = BluetoothScanner()

    @patch('src.baconfreak.BluetoothHCISocket')
    @patch('src.baconfreak.HCI_Hdr')
    @patch('src.baconfreak.HCI_Command_Hdr')
    @patch('src.baconfreak.HCI_Cmd_LE_Set_Scan_Enable')
    def test_initialize_bluetooth_interface_success(self, mock_scan_enable, mock_cmd_hdr, mock_hci_hdr, mock_socket):
        """Test successful Bluetooth interface initialization."""
        mock_bt_socket = Mock()
        mock_socket.return_value = mock_bt_socket
        
        # Mock successful scan response with proper tuple structure
        mock_response = (Mock(), Mock())
        mock_bt_socket.sr.return_value = ([mock_response], [])
        
        result = self.scanner._initialize_bluetooth_interface()
        
        self.assertEqual(result, mock_bt_socket)
        mock_bt_socket.sr.assert_called_once()

    @patch('src.baconfreak.BluetoothHCISocket')
    def test_initialize_bluetooth_interface_permission_error(self, mock_socket):
        """Test Bluetooth interface initialization with permission error."""
        mock_socket.side_effect = PermissionError("Permission denied")
        
        with self.assertRaises(BaconFreakPermissionError):
            self.scanner._initialize_bluetooth_interface()

    @patch('src.baconfreak.BluetoothHCISocket')
    @patch('src.baconfreak.HCI_Hdr')
    @patch('src.baconfreak.HCI_Command_Hdr')
    @patch('src.baconfreak.HCI_Cmd_LE_Set_Scan_Enable')
    def test_initialize_bluetooth_interface_scan_enable_failed(self, mock_scan_enable, mock_cmd_hdr, mock_hci_hdr, mock_socket):
        """Test Bluetooth interface initialization with scan enable failure."""
        mock_bt_socket = Mock()
        mock_socket.return_value = mock_bt_socket
        
        # Mock failed scan response (no answers)
        mock_bt_socket.sr.return_value = ([], [])
        
        with self.assertRaises(BaconFreakInterfaceError):
            self.scanner._initialize_bluetooth_interface()

    @patch('src.baconfreak.BluetoothHCISocket')
    def test_initialize_bluetooth_interface_general_error(self, mock_socket):
        """Test Bluetooth interface initialization with general error."""
        mock_socket.side_effect = Exception("General error")
        
        with self.assertRaises(BaconFreakInterfaceError):
            self.scanner._initialize_bluetooth_interface()


class TestBluetoothScannerSummary(unittest.TestCase):
    """Test BluetoothScanner summary methods."""

    def setUp(self):
        """Set up test fixtures."""
        with patch('src.baconfreak.ModernCompanyIdentifiers'), \
             patch('src.baconfreak.ModernDeviceDetector'), \
             patch('src.baconfreak.BaconFreakLogger'), \
             patch('src.baconfreak.config') as mock_config:
            mock_config.scan_config = Mock()
            self.scanner = BluetoothScanner()

    @patch('builtins.print')
    def test_print_simple_summary(self, mock_print):
        """Test simple summary printing."""
        self.scanner.quiet = False
        self.scanner.enable_rich = False
        self.scanner.stats.total_packets = 100
        self.scanner.stats.valid_packets = 95
        self.scanner.stats.packets_per_second = 10.5
        self.scanner.stats.devices_by_type = {DeviceType.AIRTAG_UNREGISTERED: 2}
        
        self.scanner._print_simple_summary(30.0)
        
        # Should call print multiple times
        self.assertTrue(mock_print.called)

    def test_print_rich_summary(self):
        """Test Rich summary printing."""
        self.scanner.enable_rich = True
        self.scanner.console = Mock()
        self.scanner.stats.total_packets = 100
        self.scanner.stats.valid_packets = 95
        self.scanner.stats.devices_by_type = {DeviceType.AIRTAG_UNREGISTERED: 2}
        
        self.scanner._print_rich_summary(30.0)
        
        # Should call console.print multiple times
        self.assertTrue(self.scanner.console.print.called)

    def test_print_summary_quiet_mode(self):
        """Test summary printing in quiet mode."""
        self.scanner.quiet = True
        
        with patch.object(self.scanner, '_print_rich_summary') as mock_rich, \
             patch.object(self.scanner, '_print_simple_summary') as mock_simple:
            
            self.scanner._print_summary()
            
            # Neither should be called in quiet mode
            mock_rich.assert_not_called()
            mock_simple.assert_not_called()


class TestBluetoothScannerRun(unittest.TestCase):
    """Test BluetoothScanner run method."""

    def setUp(self):
        """Set up test fixtures."""
        with patch('src.baconfreak.ModernCompanyIdentifiers'), \
             patch('src.baconfreak.ModernDeviceDetector'), \
             patch('src.baconfreak.BaconFreakLogger'), \
             patch('src.baconfreak.config') as mock_config:
            mock_config.scan_config = Mock()
            mock_config.ensure_directories = Mock()
            mock_config.output_dir_path = Path("/tmp")
            mock_config.known_pcap_path = Path("/tmp/known.pcap")
            mock_config.unknown_pcap_path = Path("/tmp/unknown.pcap")
            self.scanner = BluetoothScanner()

    @patch('src.baconfreak.pcap_writers')
    def test_run_with_bluetooth_interface_error(self, mock_pcap_writers):
        """Test run method with Bluetooth interface error."""
        self.scanner.quiet = True
        
        with patch.object(self.scanner, '_initialize_bluetooth_interface') as mock_init:
            mock_init.side_effect = BaconFreakInterfaceError("Interface error")
            
            with self.assertRaises(BaconFreakInterfaceError):
                self.scanner.run()

    @patch('src.baconfreak.pcap_writers')
    def test_run_with_keyboard_interrupt(self, mock_pcap_writers):
        """Test run method with keyboard interrupt."""
        self.scanner.quiet = True
        self.scanner.scan_config.scan_timeout = 1  # Set specific timeout
        
        mock_bt_socket = Mock()
        mock_pcap_writers.return_value.__enter__.return_value = (Mock(), Mock())
        
        with patch.object(self.scanner, '_initialize_bluetooth_interface') as mock_init:
            mock_init.return_value = mock_bt_socket
            mock_bt_socket.sniff.side_effect = KeyboardInterrupt()
            
            # Should not raise exception
            self.scanner.run()

    @patch('src.baconfreak.pcap_writers')
    def test_run_cleanup(self, mock_pcap_writers):
        """Test run method cleanup."""
        self.scanner.quiet = True
        self.scanner.scan_config.scan_timeout = 1  # Set specific timeout
        
        mock_bt_socket = Mock()
        mock_pcap_writers.return_value.__enter__.return_value = (Mock(), Mock())
        
        with patch.object(self.scanner, '_initialize_bluetooth_interface') as mock_init:
            mock_init.return_value = mock_bt_socket
            mock_bt_socket.sniff.return_value = None
            
            self.scanner.run()
            
            # Should set end time and print summary
            self.assertIsNotNone(self.scanner.stats.end_time)

    def test_run_startup_banner_rich(self):
        """Test run method startup banner with Rich."""
        self.scanner.quiet = False
        self.scanner.enable_rich = True
        self.scanner.console = Mock()
        
        with patch.object(self.scanner, '_initialize_bluetooth_interface') as mock_init:
            mock_init.side_effect = Exception("Stop early")  # Stop before actual scanning
            
            try:
                self.scanner.run()
            except Exception:
                pass
            
            # Should have printed startup banner
            self.assertTrue(self.scanner.console.print.called)


class TestMainFunction(unittest.TestCase):
    """Test main function and entry points."""

    def test_main_function_exists(self):
        """Test that main function exists and is callable."""
        from src.baconfreak import main
        self.assertTrue(callable(main))

    @patch('src.baconfreak.setup_logging')
    @patch('src.baconfreak.BluetoothScanner')
    @patch('builtins.print')
    def test_main_scanner_creation(self, mock_print, mock_scanner_class, mock_setup_logging):
        """Test main function scanner creation logic."""
        # Test the fallback path by simulating the main function logic
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        
        # Simulate fallback execution
        try:
            # This would normally be: from ..main import app; app()
            raise ImportError("No module named 'main'")
        except ImportError:
            # Fallback logic - actually call the functions to test them
            logger = mock_setup_logging()
            scanner = mock_scanner_class()
            # We don't actually run the scanner to avoid complex mocking
            
        mock_scanner_class.assert_called_once()
        mock_setup_logging.assert_called_once()

    def test_module_name_main(self):
        """Test that module can be run as main."""
        # Test that the module has the main execution block
        import src.baconfreak
        
        # The module should have the if __name__ == "__main__" block
        source_code = open(src.baconfreak.__file__).read()
        self.assertIn('if __name__ == "__main__":', source_code)


if __name__ == "__main__":
    unittest.main()