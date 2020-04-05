import os
import json
from pathlib import Path


def get_source_file_list(path):
    file_list = []
    if os.path.isdir(path):
        for subpath in Path(path).rglob('*.c'):
            file_list.append(subpath.name)
    elif os.path.isfile(path):
        if "compile_commands.json" not in path:
            return
        with open(path) as f:
            json_array = json.load(f)
            for item in json_array:
                file_list.append(item['file'])

    print(len(file_list))
    print(file_list)
    return file_list

def count_syscalls(path):
    file_list = get_source_file_list(path)


