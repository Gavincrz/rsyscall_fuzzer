import os
import json


def generate_value(operator, value):
    add_set = set()
    add_set.add(value)
    if operator == "==":
        add_set.add(value+1)
        add_set.add(value-1)
    if operator == ">" or operator == "<=":
        add_set.add(value+1)
    if operator == "<" or operator == ">=":
        add_set.add(value-1)
    return add_set


syscall_translate = {'open': 'openat', 'prlimit': 'prlimit64'}


def generate_json(path, ori_file):
    if not os.path.exists(path):
        return

    # open original json:
    with open(ori_file) as f:
        json_dict = json.load(f)

    sys_dict = {}
    new_json = {}
    for item in json_dict['syscalls']:
        # initialize sys_dict
        sys_dict[item['name']] = {'ret_v':set()}


    # parsing generated inequations
    with open(path) as fp:
        lines = fp.readlines()
        for line in lines:
            str_arr = line.rstrip('\r\n').split(' ')
            first_part = str_arr[0]
            syscall = first_part.split('~')[0]

            operator = str_arr[1]
            value = int(str_arr[2])

            if syscall == "errno":
                # add to all ret_v
                for key, item in sys_dict.items():
                    item['ret_v'].add(-value)
                    sys_dict[key] = item
            else:
                add_set = generate_value(operator, value)
                ret_val = first_part.split('~')[1]
                trans_syscall = None
                if syscall in syscall_translate.keys():
                    trans_syscall = syscall_translate[syscall]

                # get original set
                ori_dict = sys_dict.get(syscall)
                if ori_dict is None:
                    if trans_syscall is None:
                        print(f'syscall not recorded in original set {syscall}')
                else:
                    if ori_dict.get(ret_val) is not None:
                        ori_dict[ret_val].update(add_set)
                    else:
                        ori_dict[ret_val] = add_set
                    sys_dict[syscall] = ori_dict

                # add translate syscall
                if trans_syscall is not None:
                    ori_dict = sys_dict[trans_syscall]
                    if ori_dict.get(ret_val) is not None:
                        ori_dict[ret_val].update(add_set)
                    else:
                        ori_dict[ret_val] = add_set
                    sys_dict[trans_syscall] = ori_dict


    syscall_list = []
    # write sys_dict to new_json
    for key, item in sys_dict.items():
        temp_dict = {'name': key}
        for key2, item2 in item.items():
            temp_dict[key2] = list(item2)
        syscall_list.append(temp_dict)
    new_json['syscalls'] = syscall_list
    print(new_json)
    with open('/home/gavin/syscall_g.json', 'w+') as f:
        json.dump(new_json, f, indent=2)



