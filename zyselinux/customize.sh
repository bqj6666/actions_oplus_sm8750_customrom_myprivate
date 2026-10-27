#!/system/bin/sh
# Magisk/KernelSU 安装脚本：只做权限设置，无副作用
SKIPUNZIP=0
set_perm_recursive $MODPATH 0 0 0755 0644
set_perm_recursive $MODPATH/zygisk 0 0 0755 0644
