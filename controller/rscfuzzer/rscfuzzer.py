#!/usr/bin/env python3

import argparse
import logging
import yaml
import sys

log = logging.getLogger(__name__)


def load_yaml_file(yaml_file):
    """ parsing the yaml config file """
    try:
        with open(yaml_file, 'r') as stream:
            config = yaml.safe_load(stream)
    except IOError as err:
        print(f"Unable to open yaml file {yaml_file}: {err}")
        sys.exit()
    except yaml.YAMLError as err:
        print(f"Unable to load yaml file {yaml_file}: {err}")
    else:
        return config


def parse_cmd():
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

    args = parser.parse_args()
    config = load_yaml_file(args.config)

    # Setting logger with the argument values
    formatter = logging.Formatter(
        '[%(levelname)s] %(asctime)s (%(process)d:%(threadName)s) '
        '%(filename)s:%(funcName)s:%(lineno)s - %(message)s')

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(args.loglevel)
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(config['log_file'])
    file_handler.setLevel(logging.DEBUG)  # log everything to the file
    file_handler.setFormatter(formatter)

    log.addHandler(file_handler)
    log.addHandler(stream_handler)


def main():
    parse_cmd()


if __name__ == "__main__":
    main()
