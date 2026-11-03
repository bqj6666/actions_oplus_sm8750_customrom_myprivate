#!/usr/bin/env python3
"""针对 msm-kernel 的两个 Kleaf 阻塞点的自愈脚本。

1) "KMI or sublevel mismatch" → 把 msm-kernel/Makefile 的 VERSION/PATCHLEVEL/SUBLEVEL
   改成与 common 一致（我们只拿模块，不关心内核版本号）。
2) "built but not copied ... @@//msm-kernel:sun_perf" → 把列出的 .ko 插入
   msm-kernel/BUILD.bazel 中 sun_perf 的 module_outs 列表。

用法: heal_msm.py <tree_root> <build-log>
输出: 做了哪些修改
"""
import re
import sys
from pathlib import Path


def read_version(makefile: Path):
    text = makefile.read_text()
    vals = {}
    for key in ('VERSION', 'PATCHLEVEL', 'SUBLEVEL'):
        m = re.search(rf'^{key}\s*=\s*(\d+)\s*$', text, re.M)
        if m:
            vals[key] = m.group(1)
    return vals


def fix_sublevel(root: Path, log: str):
    if 'KMI or sublevel mismatch' not in log:
        return None
    cm = root / 'kernel_platform/common/Makefile'
    mm = root / 'kernel_platform/msm-kernel/Makefile'
    if not (cm.exists() and mm.exists()):
        return 'sublevel: makefile missing'
    want = read_version(cm)
    if not want:
        return 'sublevel: common version not found'
    text = mm.read_text()
    for key, val in want.items():
        text = re.sub(rf'^{key}\s*=\s*\d+\s*$', f'{key} = {val}', text, count=1, flags=re.M)
    mm.write_text(text)
    return f'sublevel: msm-kernel -> {want}'


def fix_module_outs(root: Path, log: str):
    blocks = re.findall(
        r'Add these lines to the module_outs attribute of @@//msm-kernel:sun_perf:\n'
        r'((?:[ \t]*"[^"]+",[ \t]*\n)+)', log)
    names = []
    for b in blocks:
        names += re.findall(r'"([^"]+)"', b)
    names = [n for n in dict.fromkeys(names) if n.endswith('.ko')]
    if not names:
        return None
    # sun_perf 的 module_outs 实际是 sun.bzl 里的 _sun_in_tree_modules
    cands = [root / 'kernel_platform/msm-kernel/sun.bzl',
             root / 'kernel_platform/msm-kernel/BUILD.bazel']
    for p in cands:
        if not p.exists():
            continue
        s = p.read_text()
        marker = '_sun_in_tree_modules = [' if p.name == 'sun.bzl' else 'module_outs = ['
        i = s.find(marker)
        if i < 0:
            continue
        at = i + len(marker)
        window = s[at:at + 40000]
        add = [n for n in names if f'"{n}"' not in window]
        if not add:
            return f'module_outs: already present in {p.name}'
        s = s[:at] + ''.join(f'\n        "{n}",' for n in add) + s[at:]
        p.write_text(s)
        return f'module_outs: added {add} -> {p.name}'
    return 'module_outs: no list found'


def main():
    root = Path(sys.argv[1])
    log = Path(sys.argv[2]).read_text(errors='replace') if Path(sys.argv[2]).exists() else ''
    out = []
    for fn in (fix_sublevel, fix_module_outs):
        r = fn(root, log)
        if r:
            out.append(r)
    print('; '.join(out) if out else 'nothing-to-heal')


if __name__ == '__main__':
    main()
