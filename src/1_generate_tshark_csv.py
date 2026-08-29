#!/usr/bin/env python3

import sys
import os
import glob
import subprocess
import shutil
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <diretório do dataset>  (ex: datasets/e1)", file=sys.stderr)
        sys.exit(1)

    dataset_dir = sys.argv[1]
    output = os.path.join(dataset_dir, "output.csv.gz")

    if os.path.isfile(output):
        shutil.move(output, f"{output}.old")

    print("tshark start")

    pcap_files = sorted(glob.glob(os.path.join(dataset_dir, "*.pcap.gz")))

    for f in pcap_files:
        print(f"  - {os.path.basename(f)}")
        sys.stdout.flush()

        t0 = time.time()
        f_out = open(output, "ab")
        p_zcat = subprocess.Popen(["zcat", f], stdout=subprocess.PIPE)
        p_tshark = subprocess.Popen(
            ["tshark", "-r", "-", "-M", "100000", "-t", "ad",
             "-T", "fields",
             "-e", "_ws.col.Time",
             "-e", "ip.src",
             "-e", "ip.dst",
             "-e", "tcp.dstport",
             "-e", "tcp.flags.str",
             "-e", "udp.dstport",
             "-e", "icmp.type",
             "-E", "separator=,",
             "--log-level", "critical"],
            stdin=p_zcat.stdout,
            stdout=subprocess.PIPE
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
