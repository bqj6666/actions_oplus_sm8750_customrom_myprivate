// Zygisk module: hide the ODM "adbroot" SELinux domain from app UID queries.
//
// v0.3 — use the official Zygisk PLT hook API.
//   * no dlopen / dl_iterate_phdr / manual ELF parsing / mprotect
//     (v0.1 crashed system_server, v0.2 dead-locked app startup on those calls)
//   * hooks are registered in preAppSpecialize, i.e. in zygote right before the
//     app fork, so app processes and app_zygote children inherit them;
//     system_server does not go through this path and stays untouched
//   * everything is uid-gated: only uid >= 10000 is affected
//   * kill switch: /data/adb/zy_selinux/disabled

#include <jni.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <android/log.h>

#include "zygisk.hpp"

#define TAG "zy_selinux"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

namespace {

constexpr size_t kMaxCtxLen = 4096;

bool has_adbroot(const char *s) {
    if (!s)
        return false;
    // bounded scan, do not trust the pointer beyond kMaxCtxLen
    for (size_t i = 0; i < kMaxCtxLen && s[i]; ++i) {
        if (s[i] == 'a' && strncmp(s + i, "adbroot", 7) == 0)
            return true;
    }
    return false;
}

int (*g_orig_check_access)(const char *, const char *, const char *, const char *, void *) = nullptr;
int (*g_orig_setcon)(const char *) = nullptr;

int hooked_check_access(const char *scon, const char *tcon, const char *tclass,
                        const char *perm, void *auditdata) {
    if (getuid() >= 10000) {
        const char *a = scon;
        const char *b = tcon;
        if (has_adbroot(a) || has_adbroot(b)) {
            errno = EACCES;
            return -1;
        }
    }
    if (!g_orig_check_access) {
        errno = EACCES;
        return -1;
    }
    return g_orig_check_access(scon, tcon, tclass, perm, auditdata);
}

int hooked_setcon(const char *context) {
    if (getuid() >= 10000 && has_adbroot(context)) {
        errno = EINVAL;
        return -1;
    }
    if (!g_orig_setcon) {
        errno = EINVAL;
        return -1;
    }
    return g_orig_setcon(context);
}

bool disabled_by_user() {
    return access("/data/adb/zy_selinux/disabled", F_OK) == 0;
}

class SelinuxHideModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *) override { api_ = api; }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // uid is known here already, but we gate at call time as well.
        if (!api_ || disabled_by_user() || hooked_)
            return;

        struct stat st {};
        if (stat("/system/lib64/libandroid_runtime.so", &st) != 0) {
            LOGI("stat libandroid_runtime failed: %d", errno);
            return;
        }

        api_->pltHookRegister(st.st_dev, st.st_ino, "selinux_check_access",
                              reinterpret_cast<void *>(hooked_check_access),
                              reinterpret_cast<void **>(&g_orig_check_access));
        api_->pltHookRegister(st.st_dev, st.st_ino, "selinux_android_setcon",
                              reinterpret_cast<void *>(hooked_setcon),
                              reinterpret_cast<void **>(&g_orig_setcon));

        bool ok = api_->pltHookCommit();
        hooked_ = ok;
        LOGI("plt hook commit=%d orig_check_access=%p orig_setcon=%p",
             ok ? 1 : 0, reinterpret_cast<void *>(g_orig_check_access),
             reinterpret_cast<void *>(g_orig_setcon));
    }

private:
    zygisk::Api *api_ = nullptr;
    bool hooked_ = false;
};

}  // namespace

REGISTER_ZYGISK_MODULE(SelinuxHideModule)
