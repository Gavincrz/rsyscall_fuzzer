#!/usr/bin/env python3

import argparse
import logging
import yaml
import sys
import signal
import pickle
import os
from rscfuzzer.target import targets
from rscfuzzer.fuzzer import Fuzzer

log = logging.getLogger(__name__)
sc_fuzzer = None


def parse_syscov(name):
    hash_file_v = f"{name}_v.txt"
    hash_file_f = f"{name}_f.txt"
    file = open(hash_file_v, 'rb')
    dict_v = pickle.load(file)
    file.close()

    file = open(hash_file_f, 'rb')
    dict_f = pickle.load(file)
    file.close()

    new_dict = {}
    new_count = 0
    for key, value in dict_f.items():
        if key not in dict_v.keys():
            new_count += 1
            syscall = value[0]
            stack = value[2]
            # get the first call in program
            stack_list = stack.split('\n')
            recent_call = stack_list[0]
            for stack_str in stack_list:
                if '/home/gavin/' in stack_str:
                    recent_call = stack_str
                    break
            final_str = f"{syscall} {recent_call}"
            if final_str not in new_dict.keys():
                new_dict[final_str] = 1
            else:
                new_dict[final_str] = new_dict[final_str] + 1

    log.warning(f"newly added system calls: {new_count}/{len(dict_v)}, "
                f"{float(new_count) / float(len(dict_v)) * 100.0}%")
    count_2 = 0
    for item in new_dict.items():
        print(item)
        count_2 += item[1]

    print(count_2)
    print(f"length of merged set: {len(new_dict)}")


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
        default=logging.INFO,
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

    parser.add_argument(
        "-p",
        help="parsing",
        type=str, dest="parse", default=None,
    )

    args = parser.parse_args()
    config = load_yaml_file(args.config)

    # Setting logger with the argument values
    formatter = logging.Formatter(
        '[%(levelname)s] %(asctime)s (%(process)d:%(threadName)s) '
        '%(filename)s:%(funcName)s:%(lineno)s - %(message)s')

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.WARN)
    stream_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(config['log_file'])
    file_handler.setLevel(args.loglevel)  # log everything to the file
    file_handler.setFormatter(formatter)

    logging.basicConfig(level=logging.DEBUG, handlers=[file_handler, stream_handler])

    if args.test:
        target = targets[args.target]
        clients = target.get("clients")
        if clients is not None and len(clients) > 0:
            ret = clients[0]()
            print(ret)
        exit()

    if args.parse is not None:
        parse_syscov(args.parse)
        exit()

    # create and run the fuzzer
    sc_fuzzer = Fuzzer(config, args.target, args.skip)
    sc_fuzzer.run()


def main():
    signal.signal(signal.SIGINT, signal_handler)
    parse_cmd()


if __name__ == "__main__":
    main()
