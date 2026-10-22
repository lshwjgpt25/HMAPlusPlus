#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h> // For __NR_mkdirat
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <linux/errno.h>    // For EACCES and EPERM
#include <accctl.h>         // For set_priv_sel_allow and related functions
#include <uapi/linux/limits.h>   // For PATH_MAX
#include <linux/kernel.h>   // For snprintf

KPM_NAME("HMA++");
KPM_VERSION("0.0.3");
KPM_LICENSE("GPLv3");
KPM_AUTHOR("lshwjgpt");
KPM_DESCRIPTION("TG频道:https://t.me/mizhipindao&TG群组:https://t.me/mizhichat");

#define TARGET_PATH "/storage/emulated/0/Android/data/"
#define TARGET_PATH_LEN (sizeof(TARGET_PATH) - 1)

// 内置 deny list
static const char *deny_list[] = {
    "ender_you_needs_dir!!!"
};
#define DENY_LIST_SIZE (sizeof(deny_list)/sizeof(deny_list[0]))

// 检查路径是否命中 deny_list
static int is_in_deny_list(const char *path) {
    // path 形如 /storage/emulated/0/Android/data/com.xxx.xxx
    // 需提取包名部分
    const char *p = path;
    size_t prefix_len = strlen(TARGET_PATH);
    if (strncmp(p, TARGET_PATH, prefix_len) != 0) return 0;
    const char *pkg = p + prefix_len;
    // 只取包名部分（遇到 / 或 \ 或字符串结尾）
    char pkgname[128];
    size_t i = 0;
    while (*pkg && *pkg != '/' && *pkg != '\\' && i < sizeof(pkgname) - 1) {
        pkgname[i++] = *pkg++;
    }
    pkgname[i] = '\0';
    for (size_t j = 0; j < DENY_LIST_SIZE; ++j) {
        if (strcmp(pkgname, deny_list[j]) == 0) return 1;
    }
    return 0;
}

static void before_mkdirat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1); // Path to create

    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));

    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return; // Let the original syscall handle invalid paths or too long paths
    }
    filename_kernel[len] = '\0'; // Ensure null-termination

    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        // 只拦名单，其它一律放行
        if (is_in_deny_list(filename_kernel)) {
            pr_warn("[HMA++]mkdirat: Denied by deny_list to create %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -EACCES;
        }
        // 不在名单直接 return
        return;
    }
}

// chdir 钩子，只拦截 /storage/emulated/0/Android/data/ 并命中 deny_list
static void before_chdir(hook_fargs1_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 0); // chdir 第一个参数
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return;
    }
    filename_kernel[len] = '\0';
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(filename_kernel)) {
            pr_warn("[HMA++]chdir: Denied by deny_list to %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

// rmdir/unlinkat 钩子，只拦截 /storage/emulated/0/Android/data/ 并命中 deny_list
static void before_rmdir(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1); // unlinkat 第2参数
    int flags = (int)syscall_argn(args, 2); // unlinkat 第3参数
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return;
    }
    filename_kernel[len] = '\0';
    // 只拦 AT_REMOVEDIR
    if ((flags & 0x200) && strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(filename_kernel)) {
            pr_warn("[HMA++]rmdir/unlinkat: Denied by deny_list to %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

// fstatat 钩子，只拦截 /storage/emulated/0/Android/data/ 并命中 deny_list
static void before_fstatat(hook_fargs4_t *args, void *udata) {
    const char __user *filename_user = (const char __user *)syscall_argn(args, 1); // fstatat 第2参数
    char filename_kernel[PATH_MAX];
    long len = compat_strncpy_from_user(filename_kernel, filename_user, sizeof(filename_kernel));
    if (len <= 0 || len >= sizeof(filename_kernel)) {
        return;
    }
    filename_kernel[len] = '\0';
    if (strncmp(filename_kernel, TARGET_PATH, TARGET_PATH_LEN) == 0) {
        if (is_in_deny_list(filename_kernel)) {
            pr_warn("[HMA++]fstatat/stat: Denied by deny_list to %s\n", filename_kernel);
            args->skip_origin = 1;
            args->ret = -ENOENT;
        }
    }
}

static long mkdir_hook_init(const char *args, const char *event, void *__user reserved) {
    hook_err_t err;
    pr_info("[HMA++]HMA++ init. Hooking mkdirat, chdir, rmdir, fstatat...\n");
    err = hook_syscalln(__NR_mkdirat, 3, before_mkdirat, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook mkdirat: %d\n", err);
        return -EINVAL;
    }
    err = hook_syscalln(__NR_chdir, 1, before_chdir, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook chdir: %d\n", err);
        return -EINVAL;
    }
#if defined(__NR_rmdir)
    err = hook_syscalln(__NR_rmdir, 1, before_rmdir, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook rmdir: %d\n", err);
        return -EINVAL;
    }
#elif defined(__NR_unlinkat)
    err = hook_syscalln(__NR_unlinkat, 4, before_rmdir, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook unlinkat (for rmdir): %d\n", err);
        return -EINVAL;
    }
#else
#   error "No suitable syscall number for rmdir/unlinkat"
#endif
    // fstatat 兼容新旧架构
#ifdef __NR_newfstatat
    err = hook_syscalln(__NR_newfstatat, 4, before_fstatat, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook newfstatat: %d\n", err);
        return -EINVAL;
    }
#elif defined(__NR_fstatat64)
    err = hook_syscalln(__NR_fstatat64, 4, before_fstatat, NULL, NULL);
    if (err) {
        pr_err("[HMA++]Failed to hook fstatat64: %d\n", err);
        return -EINVAL;
    }
#endif
    pr_info("[HMA++]Successfully hooked mkdirat, chdir, rmdir, fstatat.\n");
    return 0;
}

static long mkdir_hook_exit(void *__user reserved) {
    pr_info("[HMA++]HMA++ exit. Unhooking mkdirat, chdir, rmdir, fstatat...\n");
    unhook_syscalln(__NR_mkdirat, before_mkdirat, NULL);
    unhook_syscalln(__NR_chdir, before_chdir, NULL);
#if defined(__NR_rmdir)
    unhook_syscalln(__NR_rmdir, before_rmdir, NULL);
#elif defined(__NR_unlinkat)
    unhook_syscalln(__NR_unlinkat, before_rmdir, NULL);
#endif
#ifdef __NR_newfstatat
    unhook_syscalln(__NR_newfstatat, before_fstatat, NULL);
#elif defined(__NR_fstatat64)
    unhook_syscalln(__NR_fstatat64, before_fstatat, NULL);
#endif
    pr_info("[HMA++]Successfully unhooked all syscalls.\n");
    return 0;
}

KPM_INIT(mkdir_hook_init);
KPM_EXIT(mkdir_hook_exit);
