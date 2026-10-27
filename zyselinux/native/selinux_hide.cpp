// Zygisk module: hide the ODM "adbroot" SELinux domain from app UID queries.
//
// Rewrite notes (v0.2):
//  * hooks are installed in APP processes only (never system_server / zygote)
//  * every ELF pointer is validated against the target library's PT_LOAD ranges
//    before it is dereferenced (v0.1 crashed system_server with SIGSEGV here)
//  * all failures are logged and are non-fatal
//  * kill switch: create /data/adb/zy_selinux/disabled to make the module a no-op

#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <android/log.h>

#include "zygisk.hpp"

#define TAG "zy_selinux"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

namespace {

constexpr uint32_t kMaxStrLen = 4096;

bool has_adbroot(const char *s) { return s && strnlen(s, kMaxStrLen) > 0 && strstr(s, "adbroot") != nullptr; }

int (*g_orig_check_access)(const char *, const char *, const char *, const char *, void *) = nullptr;
int (*g_orig_setcon)(const char *) = nullptr;

int hooked_check_access(const char *scon, const char *tcon, const char *tclass,
                        const char *perm, void *auditdata) {
    if (getuid() >= 10000 && (has_adbroot(scon) || has_adbroot(tcon))) {
        errno = EACCES;
        return -1;
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

struct PatchCtx {
    const char *sym;
    void *replacement;
    bool done;
};

struct Range {
    uintptr_t lo;
    uintptr_t hi;
    bool has(const void *p) const {
        auto v = reinterpret_cast<uintptr_t>(p);
        return v >= lo && v < hi;
    }
    bool has(uintptr_t v) const { return v >= lo && v < hi; }
};

// Translate a DT_* value into an absolute address, tolerating both
// "already relocated" and "needs load bias" conventions.
uintptr_t fix_ptr(uintptr_t value, uintptr_t bias, const Range &r) {
    if (!value)
        return 0;
    if (r.has(value))
        return value;
    if (r.has(value + bias))
        return value + bias;
    return 0;
}

int patch_cb(struct dl_phdr_info *info, size_t, void *data) {
    if (!info || !info->dlpi_name || !strstr(info->dlpi_name, "libandroid_runtime.so"))
        return 0;

    auto *ctx = static_cast<PatchCtx *>(data);
    const uintptr_t bias = info->dlpi_addr;

    // Collect the PT_LOAD span of this library.
    Range range{0, 0};
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD)
            continue;
        uintptr_t lo = bias + ph.p_vaddr;
        uintptr_t hi = lo + ph.p_memsz;
        if (!range.lo || lo < range.lo)
            range.lo = lo;
        if (hi > range.hi)
            range.hi = hi;
    }
    if (!range.lo || range.hi <= range.lo) {
        LOGI("no PT_LOAD range for %s", info->dlpi_name);
        return 0;
    }

    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_DYNAMIC)
            continue;
        if (ph.p_memsz < sizeof(ElfW(Dyn)) * 2 || ph.p_memsz > 0x10000) {
            LOGI("suspicious PT_DYNAMIC size %zu", (size_t)ph.p_memsz);
            continue;
        }
        auto *dyn = reinterpret_cast<ElfW(Dyn) *>(bias + ph.p_vaddr);
        if (!range.has(dyn))
            continue;

        uintptr_t jmprel = 0, pltrelsz = 0, symtab = 0, strtab = 0, strsz = 0;
        for (ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; ++d) {
            if (!range.has(d))
                break;
            switch (d->d_tag) {
                case DT_JMPREL:   jmprel   = d->d_un.d_ptr; break;
                case DT_PLTRELSZ: pltrelsz = d->d_un.d_val; break;
                case DT_SYMTAB:   symtab   = d->d_un.d_ptr; break;
                case DT_STRTAB:   strtab   = d->d_un.d_ptr; break;
                case DT_STRSZ:    strsz    = d->d_un.d_val; break;
                default: break;
            }
        }

        uintptr_t rela = fix_ptr(jmprel, bias, range);
        uintptr_t syms_addr = fix_ptr(symtab, bias, range);
        uintptr_t strs_addr = fix_ptr(strtab, bias, range);
        if (!rela || !syms_addr || !strs_addr) {
            LOGI("dynamic tables not resolvable (jmprel=%lx symtab=%lx strtab=%lx)",
                 (unsigned long)jmprel, (unsigned long)symtab, (unsigned long)strtab);
            continue;
        }
        if (!pltrelsz || pltrelsz > 0x200000) {
            LOGI("unexpected PLTRELSZ %lu", (unsigned long)pltrelsz);
            continue;
        }
        if (!range.has(rela) || !range.has(rela + pltrelsz) ||
            !range.has(syms_addr) || !range.has(strs_addr)) {
            LOGI("dynamic tables outside library range");
            continue;
        }

        auto *relas = reinterpret_cast<ElfW(Rela) *>(rela);
        auto *syms  = reinterpret_cast<ElfW(Sym) *>(syms_addr);
        auto *strs  = reinterpret_cast<const char *>(strs_addr);
        size_t count = pltrelsz / sizeof(ElfW(Rela));
        long page = sysconf(_SC_PAGESIZE);

        for (size_t k = 0; k < count; ++k) {
            if (ELF64_R_TYPE(relas[k].r_info) != R_AARCH64_JUMP_SLOT)
                continue;
            uintptr_t sym_idx = ELF64_R_SYM(relas[k].r_info);
            if (!range.has(reinterpret_cast<uintptr_t>(syms) + (sym_idx + 1) * sizeof(ElfW(Sym))))
                continue;
            uintptr_t name_off = syms[sym_idx].st_name;
            if (name_off >= (strsz ? strsz : 0x10000))
                continue;
            const char *name = strs + name_off;
            if (!range.has(name))
                continue;
            if (strncmp(name, ctx->sym, 64) != 0)
                continue;

            uintptr_t slot_addr = bias + relas[k].r_offset;
            if (!range.has(slot_addr) || !range.has(slot_addr + sizeof(void *))) {
                LOGI("GOT slot outside range for %s", ctx->sym);
                continue;
            }
            auto **slot = reinterpret_cast<void **>(slot_addr);
            void *page_addr = reinterpret_cast<void *>(slot_addr & ~(uintptr_t)(page - 1));
            if (mprotect(page_addr, page, PROT_READ | PROT_WRITE) != 0) {
                LOGI("mprotect RW failed for %s: %d", ctx->sym, errno);
                continue;
            }
            void *previous = *slot;
            *slot = ctx->replacement;
            mprotect(page_addr, page, PROT_READ);
            ctx->done = true;
            LOGI("patched %s (prev=%p -> %p)", ctx->sym, previous, ctx->replacement);
        }
        return 1;
    }
    return 0;
}

void install_one(const char *sym, void *replacement, void **orig_slot) {
    void *h = dlopen("libandroid_runtime.so", RTLD_NOLOAD | RTLD_NOW);
    if (!h) {
        LOGI("libandroid_runtime.so not loaded");
        return;
    }
    *orig_slot = dlsym(h, sym);
    if (!*orig_slot) {
        LOGI("dlsym(%s) failed", sym);
        dlclose(h);
        return;
    }
    PatchCtx ctx{sym, replacement, false};
    dl_iterate_phdr(patch_cb, &ctx);
    if (!ctx.done)
        LOGI("GOT entry for %s not found", sym);
    dlclose(h);
}

bool disabled_by_user() {
    return access("/data/adb/zy_selinux/disabled", F_OK) == 0;
}

void install_hooks() {
    static bool done = false;
    if (done)
        return;
    done = true;
    if (disabled_by_user()) {
        LOGI("disabled by /data/adb/zy_selinux/disabled");
        return;
    }
    install_one("selinux_check_access",
                reinterpret_cast<void *>(hooked_check_access),
                reinterpret_cast<void **>(&g_orig_check_access));
    install_one("selinux_android_setcon",
                reinterpret_cast<void *>(hooked_setcon),
                reinterpret_cast<void **>(&g_orig_setcon));
    LOGI("hooks installed (uid=%d)", getuid());
}

class SelinuxHideModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *) override { api_ = api; }
    // App processes only. system_server / zygote are deliberately untouched.
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override { install_hooks(); }

private:
    zygisk::Api *api_ = nullptr;
};

}  // namespace

REGISTER_ZYGISK_MODULE(SelinuxHideModule)
