import os
import json
import subprocess
import shlex
from pathlib import Path
import rscfuzzer.const as const
output_path = "/home/gavin/llvm_output.txt"


def get_source_file_list(path):
    file_list = []
    if os.path.isdir(path):
        for subpath in Path(path).rglob('*.c'):
            file_list.append(os.path.join(path, subpath.name))
    elif os.path.isfile(path):
        if "compile_commands.json" not in path:
            return
        with open(path) as f:
            json_array = json.load(f)
            for item in json_array:
                file_list.append(item['file'])

    print(f"{len(file_list)} files found!")
    return file_list


syscall_dict = {}


def parse_file(path):
    global syscall_dict
    with open(path) as fp:
        lines = fp.readlines()
        module = path
        for line in lines:
            if "Module: " in line:
                module = line.split(' ')[1]


def count_syscalls(path):
    global  syscall_dict
    file_list = get_source_file_list(path)
    for file in file_list:
        cmd = f"clang -Xclang -load -Xclang " \
              f"/home/gavin/syscallpass/build/syscallcounter/libSyscallCounter.so " \
              f"{file}"
        args = shlex.split(cmd)
        subprocess.run(args)
        print(cmd)

        exit()


