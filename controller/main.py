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
from rscfuzzer.syscount import *
from rscfuzzer.retgenerate import *

log = logging.getLogger(__name__)
sc_fuzzer = None


def parse_syscov(file1, file2):
    hash_file_v = file1
    hash_file_f = file2

    file = open(hash_file_v, 'rb')
    dict_v = pickle.load(file)
    file.close()

    file = open(hash_file_f, 'rb')
    dict_f = pickle.load(file)
    file.close()

    diff_dict1 = {}
    diff_dict2 = {}
    new_dict = {}
    new_count = 0
    output_str = ''
    merge_dict = dict_v.copy()
    for key, value in dict_f.items():
        if key not in dict_v.keys():
            merge_dict[key] = value
            diff_dict2[key] = value
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
                output_str += f"{syscall}\n{stack}\n"
            else:
                new_dict[final_str] = new_dict[final_str] + 1

    for key, value in dict_v.items():
        if key not in dict_f.keys():
            diff_dict1[key] = value

    log.warning(f"newly added system calls: {new_count}/{len(dict_v)}, "
                f"{float(new_count) / float(len(dict_v)) * 100.0}%")
    count_2 = 0
    for item in new_dict.items():
        print(item)
        count_2 += item[1]

    print(count_2)
    print(f"length of merged set: {len(new_dict)}")

    f = open("log_test.txt", "w+")
    f.write(output_str)

    print(f"{len(diff_dict2)} new syscall in {file2}:")
    # print(diff_dict2)

    print(f"{len(diff_dict1)} new syscall in {file1}:")
    # print(diff_dict1)

    f.write(f"{len(diff_dict2)} new syscall in {file2}:\n")
    for key, item in diff_dict2.items():
        f.write(f"{item[0]}")
        f.write(item[2])
    f.write(f"{len(diff_dict1)} new syscall in {file1}:\n")
    for key, item in diff_dict1.items():
        f.write(f"{item[0]}")
        f.write(item[2])
    f.close()

    # dump merged file
    file_m = open('hash_merge.txt', 'wb+')
    pickle.dump(merge_dict, file_m)
    file.close()
    print("file merged to hash_merge.txt")


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
        "-r",
        help="check if the syscall order is stable",
        action="store_const", dest="order", const=True, default=False,
    )

    parser.add_argument("-u", "--syscount", metavar="FILE",
                        help="Set compile file", default=None)

    parser.add_argument("-g", "--generate", metavar="FILE",
                        help="generate valid json", default=None)

    parser.add_argument(
        "-p",
        help="parsing",
        type=str, dest="parse", default=None,
    )

    parser.add_argument(
        "-m",
        help="merge",
        type=str, dest="merge", default=None,
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
        # microbenchmark
        sc_fuzzer = Fuzzer(config, args.target, args.skip)
        sc_fuzzer.run_magic_test()
        # sc_fuzzer.measurement = True
        # sc_fuzzer.run_measurement()
        # target = targets[args.target]
        # clients = target.get("clients")
        # if clients is not None and len(clients) > 0:
        #     ret = clients[0]()
        #     print(ret)
        exit()

    if args.syscount is not None and args.parse is None:
        count_syscalls(args.syscount)
        exit()

    if args.syscount is not None and args.parse is not None and args.generate is not None:
        compare_syscall_coverage(args.syscount, args.parse, args.generate)
        exit()

    if args.generate is not None:
        generate_json(args.generate, config['syscall_config'])
        exit()

    if args.syscount is not None and args.parse is not None:
        check_syscall_coverage(args.syscount, args.parse)
        exit()


    if args.parse is not None:
        parse_syscov(args.parse, args.target)
        exit()


    # create and run the fuzzer
    sc_fuzzer = Fuzzer(config, args.target, args.skip)
    if args.order:
        sc_fuzzer.check_syscall_order()
        exit()
    sc_fuzzer.run()


def main():
    signal.signal(signal.SIGINT, signal_handler)
    parse_cmd()


if __name__ == "__main__":
    main()
