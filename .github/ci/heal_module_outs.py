#!/usr/bin/env python3
"""Kleaf 自愈：把日志里「built but not copied」的模块补进 common/BUILD.bazel 的 module_outs。

用法: heal_module_outs.py <build-log> <common/BUILD.bazel>
输出: 补进去的条目数（0 = 没东西可补）
"""
import re
import sys


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
    pos = src.find('name = "kernel_aarch64"')
    marker = 'module_outs = ['
    mo = src.find(marker, pos if pos >= 0 else 0)
    if mo < 0:
        print(-1)
        return
    ins = mo + len(marker)
    window = src[mo:mo + 8000]
    added = [n for n in names if f'"{n}"' not in window]
    if not added:
        print(0)
        return
    add = ''.join(f'\n        "{n}",' for n in added)
    src = src[:ins] + add + src[ins:]
    open(build_path, 'w').write(src)
    print(len(added))


if __name__ == '__main__':
    main()
