#!/usr/bin/env python3
"""Kleaf 自愈：把「built but not copied」的模块补进 //common:kernel_aarch64 的 module_outs。

common/BUILD.bazel 的结构是：
    define_common_kernels(target_configs = {
        "kernel_aarch64": {
            "kmi_symbol_list_strict_mode": True,
            ...
            "module_implicit_outs": get_gki_modules_list("arm64") + ...,
所以没有现成的 module_outs 列表，需要往 kernel_aarch64 这个 dict 里插一个键。

用法: heal_module_outs.py <build-log> <common/BUILD.bazel>
输出: 补进去的条目数（0 = 没东西可补，负数 = 没找到插入点）
"""
import re
import sys

KEY = '"kernel_aarch64": {'


def main():
    log_path, build_path = sys.argv[1], sys.argv[2]
    try:
        text = open(log_path, errors='replace').read()
    except FileNotFoundError:
        print(0)
        return

    blocks = re.findall(
        r'Add these lines to the module_outs attribute of [^\n]*:\n((?:[ \t]*"[^"]+",[ \t]*\n)+)',
        text)
    names = []
    for blk in blocks:
        names += re.findall(r'"([^"]+)"', blk)
    names = [n for n in dict.fromkeys(names) if n.endswith('.ko')]
    if not names:
        print(0)
        return

    src = open(build_path).read()
    i = src.find(KEY)
    if i < 0:
        print(-1)
        return

    # 已经有 module_outs 键（本函数上一轮插过）→ 合并
    m = re.search(r'"module_outs": \[([^\]]*)\]', src[i:i + 6000])
    if m:
        existing = re.findall(r'"([^"]+)"', m.group(1))
        add = [n for n in names if n not in existing]
        if not add:
            print(0)
            return
        merged = existing + add
        body = ''.join(f'\n            "{n}",' for n in merged) + '\n        '
        start = i + m.start(1)
        end = i + m.end(1)
        src = src[:start] + body + src[end:]
        open(build_path, 'w').write(src)
        print(len(add))
        return

    # 没有 → 插在 module_implicit_outs 之前
    j = src.find('"module_implicit_outs"', i)
    if j < 0 or j - i > 6000:
        print(-2)
        return
    body = '"module_outs": [' + ''.join(f'\n            "{n}",' for n in names) + '\n        ],\n        '
    src = src[:j] + body + src[j:]
    open(build_path, 'w').write(src)
    print(len(names))


if __name__ == '__main__':
    main()
