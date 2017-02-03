#!/usr/bin/env python2

import argparse
import os
import sys
import getopt
import shutil
import time

observed_pcaps = []

parser = argparse.ArgumentParser()
parser.add_argument("--input", "-i", help="Input folder")
parser.add_argument("--output", "-o", help="Output folder")
parser.add_argument("--period", "-p", help="Period", type=int)

# Watches the folder inputfolder for new unobserved pcap files, converts them into har format
# and enriches the resulting files by adding new information and decoding base64 strings information
# json objects. These har files are meant to be fed into the ELK stack for further analysis.
# The resulting output folder will replicate the input folder structure.


# TODO: DECODE BASE64 + ENRICH JSON


def watch_pcaps(inputfolder, outputfolder):
    for root, dirs, files in os.walk(inputfolder):
        for file in files:
            if file.endswith(".pcap") and file not in observed_pcaps:
                print "[+] File: {pcap} not yet transformed. Transforming it..".format(pcap=file)
                observed_pcaps.append(file)
                new_output_folder = os.path.join(outputfolder, root.split(inputfolder, 1)[1])

                if not os.path.exists(new_output_folder):
                    try:
                        os.makedirs(new_output_folder)
                    except OSError as exc: # Guard against race condition
                        if exc.errno != errno.EEXIST:
                            raise

                cmd = "python pcap2har {input} {output}".format(input=os.path.join(root, file), output=os.path.join(new_output_folder, file) + ".har")
                os.system(cmd)



if __name__ == '__main__':
    opts = parser.parse_args()
    while True:
        watch_pcaps(opts.input, opts.output)
        time.sleep(opts.period)
