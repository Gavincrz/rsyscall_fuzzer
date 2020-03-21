#!/usr/bin/env python3

import argparse
import logging
import yaml
import sys
import signal
import os
from rscfuzzer.target import targets
from rscfuzzer.fuzzer import Fuzzer

log = logging.getLogger(__name__)
sc_fuzzer = None


def signal_handler(sig, frame):
    global sc_fuzzer
    print('You pressed Ctrl+C, kill running servers')
    if sc_fuzzer:
        sc_fuzzer.kill_servers()
        sc_fuzzer.kill_gdb()
    sys.exit(0)


def load_yaml_file(yaml_file):
    """ parsing the yaml config file """
    try:
        with open(yaml_file, 'r') as stream:
            config = yaml.safe_load(stream)
    except IOError as err:
        sys.exit(f"Unable to open yaml file {yaml_file}: {err}")
    except yaml.YAMLError as err:
        sys.exit(f"Unable to load yaml file {yaml_file}: {err}")
    else:
        return config


def parse_cmd():
    global log, sc_fuzzer
    """ Parse command line arguments using argparse """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d", "--debug",
        help="Set loglevel to DEBUG, Print lots of debugging statements",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.WARN,
    )
    parser.add_argument(
        "-v", "--verbose",
        help="Set loglevel to INFO",
        action="store_const", dest="loglevel", const=logging.INFO,
    )
    parser.add_argument("-c", "--config", metavar="FILE",
                        help="Set config file", default='config.yaml')
    parser.add_argument('target',
                        help="target program to fuzz")
    parser.add_argument("-s", "--skip", type=int, dest="skip", default=0, help="starting skip count")

    parser.add_argument(
        "-t",
        help="secret test option",
        action="store_const", dest="test", const=True, default=False,
    )

    args = parser.parse_args()
    config = load_yaml_file(args.config)

    # Setting logger with the argument values
    formatter = logging.Formatter(
        '[%(levelname)s] %(asctime)s (%(process)d:%(threadName)s) '
        '%(filename)s:%(funcName)s:%(lineno)s - %(message)s')

    os.remove(config['log_file'])
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(args.loglevel)
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(config['log_file'])
    file_handler.setLevel(logging.DEBUG)  # log everything to the file
    file_handler.setFormatter(formatter)

    logging.basicConfig(level=logging.DEBUG, handlers=[file_handler, stream_handler])

    if args.test:
        target = targets[args.target]
        clients = target.get("clients")
        if clients is not None and len(clients) > 0:
            ret = clients[0]()
            print(ret)
        exit()
    # create and run the fuzzer
    sc_fuzzer = Fuzzer(config, args.target, args.skip)
    sc_fuzzer.run()


def main():
    signal.signal(signal.SIGINT, signal_handler)
    parse_cmd()


if __name__ == "__main__":
    main()
