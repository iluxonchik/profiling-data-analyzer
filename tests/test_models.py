import os
import unittest
from pathlib import Path
from data.models import EncryptionData

class ModelsBaseTestCase(unittest.TestCase):
    RES_DIR = Path('./test/res/')
    JSON_01_FILENAME = 'pencres_01.json'
    TEST_JSON_01_PATH = os.path.join(RES_DIR, JSON_01_FILENAME)

class EncryptionDataTestCase(ModelsBaseTestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_encryption_data_getters_client(self):
        ed = EncryptionData.Client(self.TEST_JSON_01_PATH)

        # we're assuming that the number of bytes sent for an entity(client or
        #   server) is constant for each evaluation
        obtained_bytes_sent = ed.get_bytes_sent_list()
        obtained_bytes_received = ed.get_bytes_received_list()

        expected_bytes_sent = [0, 901, 1]
        expected_bytes_received = [100, 200, 300]

        self.assertSequenceEqual(expected_bytes_sent, obtained_bytes_sent,
                                'Wrong bytes sent returned')
        self.assertSequenceEqual(expected_bytes_received, obtained_bytes_received,
                                'Wrong bytes received returned')

        # the iterator is only going to iterate through the funciton's
        #  profiling results data. The sent/received byte count shuould
        #  be obtained manually at the beginning
        expected_line_1 = ['RC4-128-SHA', 1992, 2005, 2001]
        expected_line_2 = ['CAMELLIA-256-GCM-SHA384', 1, 2, 3]
        expected_results = [expected_line_1, expected_line_2]
        i = 0
        for data_elem in ed:
            expected_line = expected_results[i]
            obtained_line = ed.get_results_line()
            self.assertSequenceEqual(expected_line, obtained_line,
                                    'Wrong line returned')
            i += 1

    def test_encryption_data_getters_server(self):
        ed = EncryptionData.Server(self.TEST_JSON_01_PATH)

        # we're assuming that the number of bytes sent for an entity(client or
        #   server) is constant for each evaluation
        obtained_bytes_sent = ed.get_bytes_sent_list()
        obtained_bytes_received = ed.get_bytes_received_list()

        expected_bytes_sent = [10, 11, 12]
        expected_bytes_received = [100, 200, 300]

        self.assertSequenceEqual(expected_bytes_sent, obtained_bytes_sent,
                                'Wrong bytes sent returned')
        self.assertSequenceEqual(expected_bytes_received, obtained_bytes_received,
                                'Wrong bytes received returned')

        # the iterator is only going to iterate through the funciton's
        #  profiling results data. The sent/received byte count shuould
        #  be obtained manually at the beginning
        expected_line_1 = ['RC4-128-SHA', 1234, 5678, 90]
        expected_line_2 = ['CAMELLIA-256-GCM-SHA384', 1992, 2005, 2001]
        expected_results = [expected_line_1, expected_line_2]
        i = 0
        for data_elem in ed:
            expected_line = expected_results[i]
            obtained_line = ed.get_results_line()
            self.assertSequenceEqual(expected_line, obtained_line,
                                    'Wrong line returned')
            i += 1

    def test_encryption_data_sent_bytes_result_client(self):
        BYTES_SENT_PREFIX = 'bytes sent'
        ed = EncryptionData.Client(self.TEST_JSON_01_PATH,
                                  bytes_sent_prefix=BYTES_SENT_PREFIX)
        obtained_xlxs_result = ed.get_xlxs_bytes_sent_result()
        expected_xlsx_result = (
            [BYTES_SENT_PREFIX, 0, 901, 1],
            ['RC4-128-SHA', 1992, 2005, 2001],
            ['CAMELLIA-256-GCM-SHA384', 1, 2, 3],

        )

        self.assertSequenceEqual(expected_xlsx_result, obtained_xlxs_result,
                                'Wrong XLXS result.')

    def test_encryption_data_sent_bytes_result_client_custom_regex(self):

        def regex_func(raw_str, regex):
            return 'abc'

        BYTES_SENT_PREFIX = 'bytes sent'
        ed = EncryptionData.Client(self.TEST_JSON_01_PATH,
                                  bytes_sent_prefix=BYTES_SENT_PREFIX,
                                  encr_alg_regex = regex_func)
        obtained_xlxs_result = ed.get_xlxs_bytes_sent_result()
        expected_xlsx_result = (
            [BYTES_SENT_PREFIX, 0, 901, 1],
            ['abc', 1992, 2005, 2001],
            ['abc', 1, 2, 3],

        )

        self.assertSequenceEqual(expected_xlsx_result, obtained_xlxs_result,
                                'Wrong XLXS result. ')



    def test_encryption_data_sent_bytes_result_server(self):
        BYTES_SENT_PREFIX = 'bytes sent'
        ed = EncryptionData.Client(self.TEST_JSON_01_PATH,
        bytes_sent_prefix=BYTES_SENT_PREFIX)
        obtained_xlxs_result = ed.get_xlxs_bytes_sent_result()
        expected_xlsx_result = (
        [BYTES_SENT_PREFIX, 10, 11, 12],
        ['RC4-128-SHA', 1234, 5678, 90],
        ['CAMELLIA-256-GCM-SHA384', 1992, 2005, 2001],
        )

        self.assertSequenceEqual(expected_xlsx_result, obtained_xlxs_result,
        'Wrong XLXS result.')

    def test_encryption_data_sent_bytes_result_server_with_custom_regex(self):

        def regex_func(raw_str, regex):
            return 'abc'

        BYTES_SENT_PREFIX = 'bytes sent'
        ed = EncryptionData.Client(self.TEST_JSON_01_PATH,
        bytes_sent_prefix=BYTES_SENT_PREFIX,
        bytes_sent_regex=regex_func)
        obtained_xlxs_result = ed.get_xlxs_bytes_sent_result()
        expected_xlsx_result = (
        [BYTES_SENT_PREFIX, 10, 11, 12],
        ['RC4-128-SHA', 1234, 5678, 90],
        ['CAMELLIA-256-GCM-SHA384', 1992, 2005, 2001],
        )

        self.assertSequenceEqual(expected_xlsx_result, obtained_xlxs_result,
        'Wrong XLXS result.')

    def test_encryption_data_received_bytes_result_client(self):
        BYTES_RECEIVED_PREFIX = 'bytes received'
        ed = EncryptionData.Client(self.TEST_JSON_01_PATH,
                                  BYTES_RECEIVED_PREFIX=BYTES_RECEIVED_PREFIX)
        obtained_xlxs_result = ed.get_xlxs_bytes_sent_result()
        expected_xlsx_result = (
            [BYTES_RECEIVED_PREFIX, 100, 200, 300],
            ['RC4-128-SHA', 1992, 2005, 2001],
            ['CAMELLIA-256-GCM-SHA384', 1, 2, 3],

        )

        self.assertSequenceEqual(expected_xlsx_result, obtained_xlxs_result,
                                'Wrong XLXS result.')

    def test_encryption_data_sent_bytes_result_client_custom_regex(self):

        def regex_func(raw_str, regex):
            return 'abc'

        BYTES_RECEIVED_PREFIX = 'bytes received'
        ed = EncryptionData.Client(self.TEST_JSON_01_PATH,
                                  BYTES_RECEIVED_PREFIX=BYTES_RECEIVED_PREFIX,
                                  encr_alg_regex = regex_func)
        obtained_xlxs_result = ed.get_xlxs_bytes_sent_result()
        expected_xlsx_result = (
            [BYTES_RECEIVED_PREFIX, 100, 200, 300],
            ['abc', 1992, 2005, 2001],
            ['abc', 1, 2, 3],

        )

        self.assertSequenceEqual(expected_xlsx_result, obtained_xlxs_result,
                                'Wrong XLXS result. ')

    def test_encryption_data_sent_bytes_result_server(self):
        BYTES_RECEIVED_PREFIX = 'bytes received'
        ed = EncryptionData.Client(self.TEST_JSON_01_PATH,
        BYTES_RECEIVED_PREFIX=BYTES_RECEIVED_PREFIX)
        obtained_xlxs_result = ed.get_xlxs_bytes_sent_result()
        expected_xlsx_result = (
        [BYTES_RECEIVED_PREFIX, 100, 200, 300],
        ['RC4-128-SHA', 1234, 5678, 90],
        ['CAMELLIA-256-GCM-SHA384', 1992, 2005, 2001],
        )

        self.assertSequenceEqual(expected_xlsx_result, obtained_xlxs_result,
        'Wrong XLXS result.')

    def test_encryption_data_sent_bytes_result_server_with_custom_regex(self):

        def regex_func(raw_str, regex):
            return 'abc'

        BYTES_RECEIVED_PREFIX = 'bytes received'
        ed = EncryptionData.Client(self.TEST_JSON_01_PATH,
        BYTES_RECEIVED_PREFIX=BYTES_RECEIVED_PREFIX,
        bytes_sent_regex=regex_func)
        obtained_xlxs_result = ed.get_xlxs_bytes_sent_result()
        expected_xlsx_result = (
        [BYTES_RECEIVED_PREFIX, 100, 200, 300],
        ['RC4-128-SHA', 1234, 5678, 90],
        ['CAMELLIA-256-GCM-SHA384', 1992, 2005, 2001],
        )

        self.assertSequenceEqual(expected_xlsx_result, obtained_xlxs_result,
        'Wrong XLXS result.')
