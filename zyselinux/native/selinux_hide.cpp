// Zygisk module: hide the ODM "adbroot" SELinux domain from app UID queries.
//
// Rationale: on this ROM /odm/etc/selinux/precompiled_sepolicy ships the
// adbroot types (adbroot / adbroot_service / adbroot_data_file / adbroot_exec).
// Root detectors treat "adbroot is a valid context" and
// "adbd -> adbroot binder allowed" as privileged-policy evidence.
// We answer for app UIDs as if that domain did not exist.

#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <android/log.h>

#include "zygisk.hpp"

#define TAG "zy_selinux"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

namespace {

bool has_adbroot(const char *s) { return s && strstr(s, "adbroot") != nullptr; }

int (*g_orig_check_access)(const char *, const char *, const char *, const char *, void *) = nullptr;
int (*g_orig_setcon)(const char *) = nullptr;

int hooked_check_access(const char *scon, const char *tcon, const char *tclass,
                        const char *perm, void *auditdata) {
    if (getuid() >= 10000 && (has_adbroot(scon) || has_adbroot(tcon))) {
        errno = EACCES;  // behave like "no such allow rule"
        return -1;
    }
    return g_orig_check_access(scon, tcon, tclass, perm, auditdata);
}

int hooked_setcon(const char *context) {
    if (getuid() >= 10000 && has_adbroot(context)) {
        errno = EINVAL;  // behave like "unknown context"
        return -1;
    }
    return g_orig_setcon(context);
}

struct PatchCtx {
    const char *sym;
    void *replacement;
    bool done;
};

int patch_cb(struct dl_phdr_info *info, size_t, void *data) {
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libandroid_runtime.so"))
        return 0;
    auto *ctx = static_cast<PatchCtx *>(data);
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_DYNAMIC)
            continue;
        auto *dyn = reinterpret_cast<ElfW(Dyn) *>(info->dlpi_addr + ph.p_vaddr);
        ElfW(Addr) jmprel = 0, pltrelsz = 0, symtab = 0, strtab = 0;
        for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; ++d) {
            switch (d->d_tag) {
                case DT_JMPREL:  jmprel   = d->d_un.d_ptr; break;
                case DT_PLTRELSZ: pltrelsz = d->d_un.d_val; break;
                case DT_SYMTAB:  symtab   = d->d_un.d_ptr; break;
                case DT_STRTAB:  strtab   = d->d_un.d_ptr; break;
                default: break;
            }
        }
        if (!jmprel || !symtab || !strtab)
            continue;
        auto *relas = reinterpret_cast<ElfW(Rela) *>(jmprel);
        auto *syms  = reinterpret_cast<ElfW(Sym) *>(symtab);
        auto *strs  = reinterpret_cast<const char *>(strtab);
        size_t count = pltrelsz / sizeof(ElfW(Rela));
        long page = sysconf(_SC_PAGESIZE);
        for (size_t k = 0; k < count; ++k) {
            if (ELF64_R_TYPE(relas[k].r_info) != R_AARCH64_JUMP_SLOT)
                continue;
            const char *name = strs + syms[ELF64_R_SYM(relas[k].r_info)].st_name;
            if (strcmp(name, ctx->sym) != 0)
                continue;
            auto **slot = reinterpret_cast<void **>(info->dlpi_addr + relas[k].r_offset);
            void *page_addr = reinterpret_cast<void *>(
                reinterpret_cast<uintptr_t>(slot) & ~(uintptr_t)(page - 1));
            if (mprotect(page_addr, page, PROT_READ | PROT_WRITE) != 0) {
                LOGI("mprotect failed for %s", ctx->sym);
                continue;
            }
            *slot = ctx->replacement;
            mprotect(page_addr, page, PROT_READ);
            ctx->done = true;
            LOGI("patched GOT entry: %s", ctx->sym);
        }
        return 1;
    }
    return 0;
}

void install_one(const char *sym, void *replacement, void **orig_slot) {
    void *h = dlopen("libandroid_runtime.so", RTLD_NOLOAD | RTLD_NOW);
    if (!h)
        return;
    *orig_slot = dlsym(h, sym);
    if (*orig_slot) {
        PatchCtx ctx{sym, replacement, false};
        dl_iterate_phdr(patch_cb, &ctx);
    }
    dlclose(h);
}

void install_hooks() {
    static bool done = false;
    if (done)
        return;
    done = true;
    install_one("selinux_check_access",
                reinterpret_cast<void *>(hooked_check_access),
                reinterpret_cast<void **>(&g_orig_check_access));
    install_one("selinux_android_setcon",
                reinterpret_cast<void *>(hooked_setcon),
                reinterpret_cast<void **>(&g_orig_setcon));
}

class SelinuxHideModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *) override { api_ = api; }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override { install_hooks(); }
    void postServerSpecialize(const zygisk::ServerSpecializeArgs *) override { install_hooks(); }

private:
    zygisk::Api *api_ = nullptr;
};

}  // namespace

REGISTER_ZYGISK_MODULE(SelinuxHideModule)
