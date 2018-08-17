"""
Module containing data models which can be used to query the JSON files
containing the profiling information.
"""
import re
import numpy

from utils import parse_json_file_to_dict


class Defaults(object):

    DEFAULT_BYTES_SENT_LABEL = 'bytes sent'
    DEFAULT_BYTES_RECEIVED_LABEL = 'bytes received'

    @staticmethod
    def default_ciphersuite_label(ciphersuite_str):
        REGEX = r'WITH\-(?P<encr_name>.*)'
        pattern = re.compile(REGEX)
        res = pattern.search(ciphersuite_str)
        return res.group('encr_name')

class EncryptionDataContainer(object):

    class EntityDTO(object):

        def __init__(self, bytes_sent, bytes_received, profiling_results):
            self._bytes_sent = bytes_sent
            self._bytes_received = bytes_received
            self._profiling_results = profiling_results

        @property
        def bytes_sent(self):
            return self._bytes_sent

        @property
        def bytes_received(self):
            return self._bytes_received

        @property
        def profiling_results(self):
            return self._profiling_results

    def __init__(self, json_path, bytes_sent_label, bytes_received_label,
                ciphersuite_label_fn):
        self._json_path = json_path
        self._bytes_sent_label = bytes_sent_label
        self._bytes_received_label = bytes_received_label
        self._ciphersuite_label_fn = ciphersuite_label_fn

        self._client_bytes_sent = None
        self._client_bytes_received = None
        self._client_profiling_results = None

        self._server_bytes_sent = None
        self._server_bytes_received = None
        self._server_profiling_results = None

        self._is_parsed = False

    @property
    def client_bytes_sent(self):
        return self._client_bytes_sent

    @property
    def client_bytes_received(self):
        return self._client_bytes_received

    @property
    def client_profiling_results(self):
        return self._client_profiling_results

    @property
    def server_bytes_sent(self):
        return self._server_bytes_sent

    @property
    def server_bytes_received(self):
        return self._server_bytes_received

    @property
    def server_profiling_results(self):
        return self._server_profiling_results
    
    def _get_entity_function_data(self, data, entity):
        entity_data = data[entity]
        return list(entity_data.values())[0]

    def _parse_entity_bytes_sent_and_received(self, data, entity):
        bytes_sent = [self._bytes_sent_label]
        bytes_received = [self._bytes_received_label]

        fn_data = self._get_entity_function_data(data, entity)

        first_entry = list(fn_data.values())[0]

        for bytes in first_entry.keys():
            bytes_sent.append(bytes[0])
            bytes_received.append(bytes[1])

        return bytes_sent, bytes_received

    def _parse_entity_profiling_results(self, data, entity, 
                                        bytes_sent, bytes_received):
        assert len(bytes_sent) == len(bytes_received)
        byte_pairs = []
        for i in range(len(bytes_sent)):
            byte_pairs.append((bytes_sent[i], bytes_received[i]))

        fn_data = self._get_entity_function_data(data, entity)
        profiling_results = []
        for cipher_name, cipher_profiling in fn_data.items():
            cipher_label = self._ciphersuite_label_fn(cipher_name)
            
            bytes_profres_map = {}
            for cipher_byte_pair, profiling_res in cipher_profiling.items():
                bytes_profres_map[cipher_byte_pair] = profiling_res

            cipher_profiling_values = [bytes_profres_map[pair] for pair in byte_pairs] 
            profiling_results.append([cipher_label, *cipher_profiling_values])

        return profiling_results


    def _parse_entity(self, data, entity):
        bytes_sent, bytes_received = self._parse_entity_bytes_sent_and_received(
                                                                                data, 
                                                                                entity)
        profiling_results = self._parse_entity_profiling_results(data, 
                                                                 entity,
                                                                 bytes_sent[1:],
                                                                 bytes_received[1:])

        return self.EntityDTO(bytes_sent, bytes_received, profiling_results)

    def parse(self):
        data = parse_json_file_to_dict(self._json_path)

        client_parsing_res = self._parse_entity(data, 'client')
        server_parsing_res = self._parse_entity(data, 'server')

        self._client_bytes_sent = client_parsing_res.bytes_sent
        self._client_bytes_received = client_parsing_res.bytes_received
        self._client_profiling_results = client_parsing_res.profiling_results

        self._server_bytes_sent = server_parsing_res.bytes_sent
        self._server_bytes_received = server_parsing_res.bytes_received
        self._server_profiling_results = server_parsing_res.profiling_results

        self._is_parsed = True

    def parse_if_not_parsed(self):
        if self._is_parsed:
            return
        self.parse()

class EncryptionData(object):

    def __init__(self, json_path,
                bytes_sent_label=Defaults.DEFAULT_BYTES_SENT_LABEL,
                bytes_received_label=Defaults.DEFAULT_BYTES_RECEIVED_LABEL,
                ciphersuite_label_fn=Defaults.default_ciphersuite_label):
        self._container = EncryptionDataContainer(
                                                 json_path,
                                                 bytes_sent_label,
                                                 bytes_received_label,
                                                 ciphersuite_label_fn)
        self._is_parsed = False

    def client(self):
        for client_res in self._container.client_profiling_results:
            yield client_res

    def server(self):
        for server_res in self._container.server_profiling_results:
            yield server_res

    def _sort_result_by_bytes(self, res):
        """
        Sort the final result by the first row.
        """
        # extract labels and results
        labels = [sublist[0] for sublist in res]
        mtrx_to_sort = numpy.array([sublist[1:] for sublist in res])

        # transpose matrix
        rotated_mtrx = mtrx_to_sort.transpose()
        # sort by column 0
        sorted_mtrx = sorted(rotated_mtrx, key=lambda line: line[0])
        # transpose matrix again
        sorted_and_rotated_matrix = numpy.array(sorted_mtrx).transpose()
        sorted_and_rotated_matrix = sorted_and_rotated_matrix.tolist()

        matrix_size = len(sorted_and_rotated_matrix)

        assert len(labels) == matrix_size, ('Mismatch'
                               ' in the number of labels and matrix rows.')
        # join labels and results
        res = [[labels[i]] + sorted_and_rotated_matrix[i] for i in range(matrix_size)]
        return res

    def get_client_bytes_sent_list(self):
        self._container.parse_if_not_parsed()
        return self._container.client_bytes_sent[1:]

    def get_client_bytes_received_list(self):
        self._container.parse_if_not_parsed()
        return self._container.client_bytes_received[1:]

    def get_client_xlxs_bytes_sent_result(self):
        self._container.parse_if_not_parsed()
        res = (self._container.client_bytes_sent, 
               *self._container.client_profiling_results)
        res = self._sort_result_by_bytes(res)
        return res

    def get_server_bytes_received_list(self):
        self._container.parse_if_not_parsed()
        return self._container.client_bytes_received[1:]

    def get_server_bytes_sent_list(self):
        self._container.parse_if_not_parsed()
        return self._container.server_bytes_sent[1:]

    def get_server_xlxs_bytes_sent_result(self):
        self._container.parse_if_not_parsed()
        res = (self._container.server_bytes_sent, 
               *self._container.server_profiling_results)
        res = self._sort_result_by_bytes(res)
        return res

    def get_client_xlxs_bytes_received_result(self):
        self._container.parse_if_not_parsed()
        res = (self._container.client_bytes_received,
               *self._container.client_profiling_results)
        res = self._sort_result_by_bytes(res)
        return res

    def get_server_xlxs_bytes_received_result(self):
        self._container.parse_if_not_parsed()
        res = (self._container.server_bytes_received,
               *self._container.server_profiling_results)
        res = self._sort_result_by_bytes(res)
        return res
