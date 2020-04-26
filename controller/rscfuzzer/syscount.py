import os
import json
import subprocess
import shlex
import pickle
from pathlib import Path
import re
import rscfuzzer.const as const

output_path = "/home/gavin/llvm_output.txt"
wrapper_th = 4


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


module_dict = {}
func_dict = {}


def parse_file(path):
    global module_dict, func_dict
    if not os.path.exists(path):
        return
    with open(path) as fp:
        lines = fp.readlines()
        cur_module = path
        temp_module_set = []
        temp_func_set = []
        temp_func_contain = False
        cur_function = None
        for line in lines:
            if "Module: " in line:
                cur_module = line.split(' ')[1].rstrip('\r\n')
                temp_module_set = []
                if cur_module in module_dict.keys():
                    temp_module_set = module_dict[cur_module]
            elif "Function: " in line:
                cur_function = line.split(' ')[1].rstrip('\r\n')
                temp_func_set = []
                temp_func_contain = None
                if cur_function in func_dict.keys():
                    temp_func_set = func_dict[cur_function][0]
                    temp_func_contain = func_dict[cur_function][1]
            elif "Module end" in line:
                # write back module
                module_dict[cur_module] = temp_module_set
            elif "Function end" in line:
                # write back function
                func_dict[cur_function] = [temp_func_set, temp_func_contain, 0] # set, contain syscall flag, called times
            else:
                called = line.rstrip('\r\n')
                temp_module_set.append(called)
                temp_func_set.append(called)
                if called in const.all_syscall:
                    temp_func_contain = True


def contain_syscall(func, depth=0):
    value = func_dict.get(func)
    if value is None:
        return False
    if value[1] is None:
        if depth > 10:
            func_dict[func] = [value[0], False, value[2]]
            return False
        contain = False
        for called in value[0]:
            contain = contain_syscall(called, depth+1)
            if contain:
                break
        func_dict[func] = [value[0], contain, value[2]]
        return contain
    return value[1]


def count_syscalls(path):
    parse_file(path)
    # global module_dict, func_dict
    # file_list = get_source_file_list(path)
    # for file in file_list:
    #     if os.path.exists(output_path):
    #         os.remove(output_path)
    #     cmd = f"clang -Xclang -load -Xclang " \
    #           f"/home/gavin/syscallpass/build/syscallcounter/libSyscallCounter.so " \
    #           f"{file}"
    #     args = shlex.split(cmd)
    #     subprocess.run(args)
    #     print(cmd)
    #     parse_file(output_path)
    module_count = 0
    for module, value in module_dict.items():
        syscall_count = 0
        for item in value:
            if item in const.all_syscall:
                syscall_count += 1
        if syscall_count > 0:
            module_count += 1
            print(f"module: {module} : syscall number: {syscall_count}")
    print(f"{module_count} / {len(module_dict)} contains syscalls")

    # get syscall invokation times
    for func, value in func_dict.items():
        contain_syscall(func)
        for func2 in value[0]:
            value2 = func_dict.get(func2)
            if value2 is None:
                continue
            func_dict[func2] = [value2[0], value2[1], value2[2]+1]

    func_count = 0
    called_count = 0
    wrapper_list = []
    syscall_func_list = []
    indirect_call_list = []
    wrapper_name_list = []
    for func, value in func_dict.items():
        syscall_count = 0
        for item in value[0]:
            if item in const.all_syscall:
                syscall_count += 1
        if syscall_count > 0:
            func_count += 1
            print(f"Function: {func} : syscall number: {syscall_count}")
            syscall_func_list.append(func)
        if value[1]:
            indirect_call_list.append(func)
            if value[2] >= wrapper_th:
                wrapper_name_list.append(func)
                wrapper_list.append((func, value[2]))
        if value[2] > 0:
            called_count += 1
    print(f"{func_count}/{called_count}/{len(func_dict)} functions contain syscalls")
    print(f"{len(wrapper_list)} wrapper functions when threshold = 4")
    print(wrapper_list)
    return syscall_func_list, indirect_call_list, wrapper_name_list


def compare_diff(list1, list2):
    unique1 = []
    unique2 = []
    for item in list1:
        if item not in list2:
            unique1.append(item)

    for item in list2:
        if item not in list1:
            unique2.append(item)
    print(f"unique for list1: {len(unique1)} \n{unique1}, unique2: {len(unique2)}\n{unique2}")


def compare_syscall_coverage(count_file, hash_file1, hash_file2):
    matched_func1, matched_indirect1, matched_wrapper1 = check_syscall_coverage(count_file, hash_file1)
    matched_func2, matched_indirect2, matched_wrapper2 = check_syscall_coverage(count_file, hash_file2)
    print('unique syscall func:')
    compare_diff(matched_func1, matched_func2)
    print('unique syscall indirect func:')
    compare_diff(matched_indirect1, matched_indirect2)
    print('unique wrapper func:')
    compare_diff(matched_wrapper1, matched_wrapper2)


def check_syscall_coverage(count_file, hash_file):
    syscall_func_list, indirect_list, wrapper_list = count_syscalls(count_file)

    # start parsing hash_file

    file = open(hash_file, 'rb')
    hash_dict = pickle.load(file)
    file.close()

    func_pattern = r"\((.+)\)"

    matched_func = set()
    matched_wrapper = set()
    matched_indirect = set()
    func_set = set()
    not_any_set = set()
    for key, value in hash_dict.items():
        stack_str = value[2]
        stack_list = stack_str.split('\n')
        for stack in stack_list:
            result = re.search(func_pattern, stack)
            if result is not None:
                func_name = result.group(1)
                func_name = func_name.split('.')[0].split('+')[0]
                func_set.add(func_name)
                if func_name in syscall_func_list:
                    matched_func.add(func_name)
                if func_name in indirect_list:
                    matched_indirect.add(func_name)
                else:
                    not_any_set.add(func_name)
                if func_name in wrapper_list:
                    matched_wrapper.add(func_name)

    missed_func = []
    for func in syscall_func_list:
        if func not in matched_func:
            missed_func.append(func)
    print(missed_func)

    print(f'{len(matched_func)}/{len(syscall_func_list)} '
          f'({float(len(matched_func)) / float(len(syscall_func_list)) * 100.0}%) '
          f'functions contain syscalls reached')
    print(f'{len(matched_indirect)}/{len(indirect_list)} '
          f'({float(len(matched_indirect)) / float(len(indirect_list)) * 100.0}%) '
          f'functions(have syscall in their call path) reached')
    print(f'{len(matched_wrapper)}/{len(wrapper_list)} '
          f'({float(len(matched_wrapper)) / float(len(wrapper_list)) * 100.0}%) helper functions reached')

    return matched_func, matched_indirect, matched_wrapper




