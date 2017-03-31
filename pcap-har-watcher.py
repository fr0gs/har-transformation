#!/usr/bin/env python2

import argparse
import os
import json
import sys
import getopt
import shutil
import time
import base64
import yaml


observed_pcaps = []
observed_hars = []
docker_compose_file = {}

parser = argparse.ArgumentParser()
parser.add_argument("--input", "-i", help="Input folder")
parser.add_argument("--output", "-o", help="Output folder")
parser.add_argument("--dcompose", "-dc", help="Docker compose file to enrich the HARs")
parser.add_argument("--period", "-p", help="Period", type=int)


def transform_pcaps(inputfolder, outputfolder):
    """
    Watches the folder inputfolder for new unobserved pcap files and converts them into har format.

    Args:
        inputfolder: input folder to look for pcap files.
        outputfolder: output folder to save the converted har files.

    Raises:
        OSError: if there is a race condition while making a directory in the outut folder, this error will arise.
    """
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


def parse_container_links(yml_file):
    """
    Parses a given docker-compose YML file and creates a dictionary with all the linked containers that compose the network.

    Args:
        yml_file: the docker-compose.yml file
    """

    containers = {}
    stream = file(yml_file, "r")
    drc_file = yaml.safe_load(stream)
    containers_links = { key: { elem.split(':')[0]: elem.split(':')[1] for elem in value['links'] } for (key, value) in drc_file['services'].iteritems() if 'links' in value }
    return containers_links



def enrich_hars(outputfolder):
    """
    Watches the output folder for har files and modifies them into a format suitable for ElasticSearch.

    Args:
        outputfolder: folder where to look for har files.
    """
    for root, dirs, files in os.walk(outputfolder):
        for file in files:
            if file.endswith(".har") and (not file.endswith(".trans.har")) and file not in observed_hars:
                print "[+] File: {har} not yet enriched. Enriching it..".format(har=file)
                observed_hars.append(file)
                container_name = file.split("_")[1]
                decoded = json.loads(open(os.path.join(root, file)).read())
                result = {}
                result = parse_recursive_har(decoded)
                result['meta'] = { 'container': file.split('_')[1], 'interface': file.split('_')[3] }
                if container_name == "default":
                    result['links'] = docker_compose_file
                else:
                    if container_name in docker_compose_file:
                        result['links'] = docker_compose_file[container_name]

                newname = file[:-4] + '.trans.har'
                with open(os.path.join(root, newname), 'w') as f:
                    json.dump(result, f, indent=2, encoding='utf8', sort_keys=True)
                    f.write('\n')


def parse_recursive_har(har, isBase64 = False):
    """
    Transform the har object converting every object array into an object with numeric keys.

    Args:
        har: a single HAR (json) object.
    """
    result = {}
    for attr, value in har.iteritems():
        if (type(har[attr]) is dict) and (attr == "content"):
            if "encoding" in har[attr].keys() and har[attr]["encoding"] == "base64":
                result[attr] = parse_recursive_har(har[attr], True)
        elif type(har[attr]) is dict:
            result[attr] = parse_recursive_har(har[attr])
        elif type(har[attr]) is list:
            result[attr] = {}
            for i, val in enumerate(har[attr]):
                result[attr][str(i)] = parse_recursive_har(val)
        else:
            if attr == "text" and isBase64 == True:
                result[attr] = base64.b64decode(value)
            else:
                result[attr] = value
    return result


if __name__ == '__main__':
    opts = parser.parse_args()
    docker_compose_file = parse_container_links(opts.dcompose)
    print docker_compose_file
    while True:
        transform_pcaps(opts.input, opts.output)
        enrich_hars(opts.output)
        time.sleep(opts.period)
