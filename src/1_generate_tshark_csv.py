#!/usr/bin/env python3

import argparse
import glob
import os
import subprocess
import sys
import shutil
import time


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extrai campos relevantes de pacotes .pcap.gz via tshark.",
    )
    parser.add_argument(
        "dataset_dir",
        help="Diretório contendo arquivos .pcap.gz (ex: datasets/e3_subset)",
    )
    parser.add_argument(
        "--max-pcap-files",
        type=int,
        default=None,
        help="Número máximo de arquivos .pcap.gz a processar (padrão: todos)",
    )
    parser.add_argument(
        "--packet-limit",
        type=int,
        default=None,
        help="Limite de pacotes por arquivo .pcap.gz, repassado ao tshark via -c (ex: 50000)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    dataset_dir = args.dataset_dir
    output = os.path.join(dataset_dir, "output.csv.gz")

    if os.path.isfile(output):
        shutil.move(output, f"{output}.old")

    print("tshark start")

    pcap_files = sorted(glob.glob(os.path.join(dataset_dir, "*.pcap.gz")))

    if args.max_pcap_files is not None:
        pcap_files = pcap_files[: args.max_pcap_files]

    if not pcap_files:
        print("Nenhum arquivo .pcap.gz encontrado.", file=sys.stderr)
        sys.exit(1)

    for f in pcap_files:
        print(f"  - {os.path.basename(f)}")
        sys.stdout.flush()

        t0 = time.time()
        f_out = open(output, "ab")

        p_zcat = subprocess.Popen(["zcat", f], stdout=subprocess.PIPE)

        tshark_cmd = [
            "tshark", "-r", "-", "-M", "100000", "-t", "ad",
            "-T", "fields",
            "-e", "_ws.col.Time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "tcp.flags.str",
            "-e", "udp.dstport",
            "-e", "icmp.type",
            "-E", "separator=,",
            "--log-level", "critical",
        ]
        if args.packet_limit is not None:
            tshark_cmd.extend(["-c", str(args.packet_limit)])

        p_tshark = subprocess.Popen(
            tshark_cmd,
            stdin=p_zcat.stdout,
            stdout=subprocess.PIPE,
        )
        p_gzip = subprocess.Popen(["gzip", "-c"], stdin=p_tshark.stdout, stdout=f_out)

        if p_zcat.stdout is not None:
            p_zcat.stdout.close()
        if p_tshark.stdout is not None:
            p_tshark.stdout.close()

        p_gzip.wait()
        p_tshark.wait()
        p_zcat.wait()
        f_out.close()

        elapsed = time.time() - t0
        print(f"    ({elapsed:.2f}s)", file=sys.stderr)

    print("tshark end")


if __name__ == "__main__":
    main()
