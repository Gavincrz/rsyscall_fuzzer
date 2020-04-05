import os
import json


def generate_json(path, ori_file):
    if not os.path.exists(path):
        return

    # open original json:
    with open(ori_file) as f:
        json_dict = json.load(f)

    new_json = {}
    new_json['syscalls'] = []
    for item in json_dict['syscalls']:
        new_json['syscalls'].append({"name": item['name']})

    with open('/home/gavin/syscall_g.json', 'w+') as f:
        json.dump(new_json, f)

    with open(path) as fp:
        lines = fp.readlines()

