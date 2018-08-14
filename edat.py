#!/usr/bin/env python3
import argparse

from utils import write_excel_to_file
from data.models import EncryptionData

def run(json_path, out_filename, is_client, is_server, is_bs, is_br):
    ed = EncryptionData(json_path)

    if is_client:
        if is_bs:
            res = ed.get_client_xlxs_bytes_sent_result()
        else:
            res = ed.get_client_xlxs_bytes_received_result()
    else:
        if is_bs:
            res = ed.get_server_xlxs_bytes_sent_result()
        else:
            res = ed.get_server_xlxs_bytes_received_result()

    write_excel_to_file(res, out_filename) 

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Encryption Data Analyzer Tool\n'
    'Reads JSON input data and outputs excel files for the specified analysis type.')

    parser.add_argument('path', type=str, help='JSON file path')
    parser.add_argument('output', type=str, help='server program path')

    entity_switcher = parser.add_mutually_exclusive_group(required=True)
    entity_switcher.add_argument('-c', '--client', default=False, action='store_true', help='use client profiling results')
    entity_switcher.add_argument('-s', '--server', default=False, action='store_true', help='user server profiling results')

    sent_received_switcher = parser.add_mutually_exclusive_group(required=True)
    sent_received_switcher.add_argument('-bs', '--bytes-sent', default=False, action='store_true', help='use bytes sent')
    sent_received_switcher.add_argument('-br', '--bytes-received', default=False, action='store_true', help='use bytes received')

    args = parser.parse_args()

    run(args.path, 
        args.output,
        args.client, 
        args.server, 
        args.bytes_sent, 
        args.bytes_received)