/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xiaojianbang_hook — Zero-trace stealth hook tool
 * Author: xiaojianbang
 * Project: xiaojianbang-stealth-hook
 *
 * Usage:
 *   xiaojianbang_hook --pid <pid> --so <name> --offset <hex>[,<hex>...] [options]
 *
 * Default behaviour: hooks the given offset(s) on ALL threads of the target
 * process (plus auto-registers new threads), then enters a live polling loop
 * that prints every new hit (args + pointer memory dump) until Ctrl+C.
 *
 * Options:
 *   --offset H[,H..]   One or more SO-relative offsets (repeatable / comma list)
 *   --dump-size N      Bytes to dump per pointer arg (default 80, max 128)
 *   --no-dump          Do not dump pointer memory, show register values only
 *   --once             Capture first hit then exit (no live loop)
 *   --listen-ret       Also capture return value via state-machine jump
 *   --modify-arg N=VAL Override register XN with VAL on entry (repeatable)
 *   --replace-ret VAL  Skip function, return VAL directly
 *   --nth N            Capture the Nth hit (skip first N-1)
 *   --query            One-shot query of current captured data, then exit
 *   --unhook           Remove all HWBPs for the offset(s), then exit
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SH_SYSCALL_MAGIC    0x584A42
#define SH_CMD_STATUS       0x0001
#define SH_CMD_HWBP_HOOK    0x1001
#define SH_CMD_HWBP_UNHOOK  0x1002
#define SH_CMD_HWBP_QUERY   0x1006
#define SH_CMD_HWBP_AUTO_THREAD 0x1007
#define SH_CMD_HWBP_SET_OVERRIDE 0x1009
#define SH_CMD_HWBP_SET_SKIP    0x100C
#define SH_CMD_HWBP_WATCH       0x100D
#define SH_CMD_HWBP_WATCH_AUTO  0x100E
#define SH_CMD_HWBP_HITS        0x100F

#define SH_WATCH_READ   0
#define SH_WATCH_WRITE  1
#define SH_WATCH_RW     2

#define SH_HITS_MAX     32
#define SH_STACK_MAX    256
#define SH_HIT_ST_WORDS 4

#define SH_HWBP_FLAG_EXECUTE    (1 << 0)
#define SH_HWBP_FLAG_LISTEN_RET (1 << 3)
#define SH_HWBP_FLAG_MODIFY_ARGS (1 << 7)
#define SH_HWBP_FLAG_SKIP_ORIGIN (1 << 8)
#define SH_STATUS_MAGIC 0x53484F4B
#define SH_VERSION_CODE 0x00010001  /* v1.0.1: watchpoints */

#define SH_DUMP_MAX     128
#define MAX_OFFSETS     16
#define MAX_TIDS        512
#define MAX_SEEN        2048

struct sh_hwbp_request {
    uint64_t target_addr;
    uint32_t target_pid;
    uint32_t flags;
    uint64_t callback_addr;
    uint64_t trampoline_addr;
    uint32_t dump_size;
    uint32_t _pad;
};

struct sh_hwbp_query {
    uint64_t target_addr;
    uint32_t tid;
    uint32_t hit_count;
    uint64_t last_pc;
    uint64_t last_x0;
    uint64_t last_x1;
    uint32_t is_disabled;
    uint32_t is_waiting_return;
    uint32_t handler_enter_count;
    uint32_t handler_unmatched_count;
    uint64_t entry_args[8];
    uint64_t ret_x0;
    uint64_t entry_lr;
    uint8_t  mem_dump[8][SH_DUMP_MAX];
    uint16_t mem_len[8];
    uint32_t node_index;
    uint32_t node_total;
};

struct sh_hwbp_override {
    uint64_t target_addr;
    uint32_t target_pid;
    uint32_t flags;
    uint64_t override_mask;
    uint64_t override_args[8];
    uint64_t ret_value;
};

/* ---- data watchpoint (keep in sync with kpm/stealth_hook.h) ---- */

struct sh_hwbp_watch {
    uint64_t watch_addr;
    uint32_t tid;
    uint32_t bp_len;
    uint32_t type;
    uint32_t stack_size;
    uint32_t max_hits;
    uint32_t flags;
    uint64_t _pad;
};

struct sh_hwbp_hit {
    uint64_t pc;
    uint64_t lr;
    uint64_t sp;
    uint64_t x[8];
    uint64_t addr;
    uint64_t val;
    uint64_t st[SH_HIT_ST_WORDS];
};

struct sh_hwbp_hits_hdr {
    uint64_t watch_addr;
    uint32_t tid;
    uint32_t node_index;
    uint32_t node_total;
    uint32_t total;
    uint32_t count;
    uint32_t stack_len;
    uint32_t bp_len;
    uint32_t is_armed;
    uint32_t hit_count;
    uint32_t ring_head;
    uint32_t max_hits;
    uint32_t _pad;
};

struct sh_hwbp_hits {
    struct sh_hwbp_hits_hdr hdr;
    struct sh_hwbp_hit entries[SH_HITS_MAX];
    uint8_t stack[SH_STACK_MAX];
};

static long sh_call(long cmd, long a1, long a2, long a3, long a4) {
    return syscall(285, SH_SYSCALL_MAGIC, cmd, a1, a2, a3, a4);
}

/* ---- live-trace dedup table: (addr,tid) -> last seen hit_count ---- */
struct seen_entry { uint64_t addr; uint32_t tid; uint32_t last_hit; };
static struct seen_entry g_seen[MAX_SEEN];
static int g_seen_count = 0;

static uint32_t seen_get(uint64_t addr, uint32_t tid) {
    for (int i = 0; i < g_seen_count; i++)
        if (g_seen[i].addr == addr && g_seen[i].tid == tid)
            return g_seen[i].last_hit;
    return 0;
}
static void seen_set(uint64_t addr, uint32_t tid, uint32_t hit) {
    for (int i = 0; i < g_seen_count; i++)
        if (g_seen[i].addr == addr && g_seen[i].tid == tid) {
            g_seen[i].last_hit = hit;
            return;
        }
    if (g_seen_count < MAX_SEEN) {
        g_seen[g_seen_count].addr = addr;
        g_seen[g_seen_count].tid = tid;
        g_seen[g_seen_count].last_hit = hit;
        g_seen_count++;
    }
}

static volatile int g_running = 1;
static void on_sigint(int sig) { (void)sig; g_running = 0; }

static uint64_t resolve_so_base(uint32_t pid, const char *so_name) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    uint64_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, so_name)) continue;
        if (strstr(line, "r-xp") || strstr(line, "rwxp")) {
            uint64_t addr_start = strtoull(line, NULL, 16);
            char *p = strchr(line, ' ');
            if (p) p = strchr(p + 1, ' ');
            uint64_t file_offset = 0;
            if (p) file_offset = strtoull(p + 1, NULL, 16);
            base = addr_start - file_offset;
            break;
        }
    }
    fclose(f);
    return base;
}

static int get_tids(uint32_t pid, uint32_t *tids, int max_tids) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ls /proc/%u/task 2>/dev/null", pid);
    FILE *p = popen(cmd, "r");
    if (!p) return 0;
    int count = 0;
    char buf[32];
    while (fgets(buf, sizeof(buf), p) && count < max_tids)
        tids[count++] = (uint32_t)strtoul(buf, NULL, 10);
    pclose(p);
    return count;
}

/* Print one hit: registers + hex dump of pointer args */
static void print_hit(uint64_t offset, struct sh_hwbp_query *q, int do_listen_ret) {
    printf("\n[0x%llx #%u] tid=%u  pc=0x%llx\n",
           (unsigned long long)offset, q->hit_count, q->tid,
           (unsigned long long)q->last_pc);
    for (int i = 0; i < 8; i++) {
        uint64_t v = q->entry_args[i];
        if (q->mem_len[i] == 0) {
            printf("  X%d=0x%llx\n", i, (unsigned long long)v);
            continue;
        }
        printf("  X%d=0x%llx →\n", i, (unsigned long long)v);
        uint16_t n = q->mem_len[i];
        for (uint16_t off = 0; off < n; off += 16) {
            printf("      %04x: ", off);
            uint16_t row = (n - off < 16) ? (n - off) : 16;
            for (uint16_t j = 0; j < 16; j++) {
                if (j < row) printf("%02x ", q->mem_dump[i][off + j]);
                else printf("   ");
                if (j == 7) printf(" ");
            }
            printf(" |");
            for (uint16_t j = 0; j < row; j++) {
                uint8_t c = q->mem_dump[i][off + j];
                printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
            }
            printf("|\n");
        }
    }
    if (do_listen_ret)
        printf("  RET=0x%llx\n", (unsigned long long)q->ret_x0);
    fflush(stdout);
}

/* Map an address to a readable "module+0xoff" label using /proc/<pid>/maps. */
static void resolve_label(uint32_t pid, uint64_t addr, char *out, size_t outlen) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(out, outlen, "0x%llx", (unsigned long long)addr); return; }

    while (fgets(line, sizeof(line), f)) {
        unsigned long long s = 0, e = 0, off = 0;
        char perms[8] = {0}, name[256] = {0};
        int n = sscanf(line, "%llx-%llx %7s %llx %*s %*s %255[^\n]", &s, &e, perms, &off, name);
        if (n < 4) continue;
        if (addr < s || addr >= e) continue;

        /* basename + mapping-relative base */
        const char *nm = name;
        while (*nm == ' ') nm++;
        if (*nm == '/') {
            const char *b = strrchr(nm, '/');
            if (b) nm = b + 1;
            uint64_t base = (uint64_t)s - (uint64_t)off;
            snprintf(out, outlen, "%s+0x%llx", nm, (unsigned long long)(addr - base));
        } else if (*nm) {
            snprintf(out, outlen, "%s+0x%llx", nm, (unsigned long long)(addr - (uint64_t)s));
        } else {
            snprintf(out, outlen, "anon:0x%llx+0x%llx", (unsigned long long)s,
                     (unsigned long long)(addr - (uint64_t)s));
        }
        fclose(f);
        return;
    }
    fclose(f);
    snprintf(out, outlen, "0x%llx (unmapped)", (unsigned long long)addr);
}

static const char *watch_type_name(uint32_t t) {
    return t == SH_WATCH_READ ? "r" : (t == SH_WATCH_RW ? "rw" : "w");
}

static void cmd_watch(uint32_t pid, uint64_t addr, uint32_t len, uint32_t type,
                      uint32_t max_hits, uint32_t stack_size, int do_auto) {
    uint32_t tids[MAX_TIDS];
    int tid_count = get_tids(pid, tids, MAX_TIDS);
    if (tid_count == 0) { fprintf(stderr, "[-] no threads for pid %u\n", pid); return; }

    int ok = 0, fail = 0;
    for (int t = 0; t < tid_count; t++) {
        struct sh_hwbp_watch w;
        memset(&w, 0, sizeof(w));
        w.watch_addr = addr;
        w.tid = tids[t];
        w.bp_len = len;
        w.type = type;
        w.stack_size = stack_size;
        w.max_hits = max_hits;
        long r = sh_call(SH_CMD_HWBP_WATCH, (long)&w, 0, 0, 0);
        if (r == 0) ok++; else fail++;
    }
    printf("[+] watch %s len=%u addr=0x%llx: armed on %d/%d threads (fail=%d)\n",
           watch_type_name(type), len, (unsigned long long)addr, ok, tid_count, fail);
    if (fail)
        printf("[!] ARM64 has only 4 watchpoint registers per thread - failures are\n"
               "[!] expected once more than 4 watchpoints are live on a thread.\n");

    if (do_auto) {
        long r = sh_call(SH_CMD_HWBP_WATCH_AUTO, (long)addr, (long)pid, (long)len, (long)type);
        if (r == 0)
            printf("[+] new threads of pid %u will inherit this watchpoint\n", pid);
        else
            printf("[!] auto-thread arm failed r=%ld (no wake_up_new_task hook?)\n", r);
    }
    fflush(stdout);
}

static void cmd_unwatch(uint32_t pid, uint64_t addr) {
    uint32_t tids[MAX_TIDS];
    int tid_count = get_tids(pid, tids, MAX_TIDS);
    int n = 0;
    for (int t = 0; t < tid_count; t++)
        if (sh_call(SH_CMD_HWBP_UNHOOK, (long)addr, (long)tids[t], 0, 0) == 0) n++;
    printf("[+] unwatched %d node(s) for 0x%llx\n", n, (unsigned long long)addr);
}

/* Print the hit ring of every watchpoint node registered at @addr. */
static void cmd_hits(uint32_t pid, uint64_t addr) {
    struct sh_hwbp_hits *h = calloc(1, sizeof(*h));
    if (!h) return;

    h->hdr.watch_addr = addr;
    h->hdr.node_index = 0;
    long r = sh_call(SH_CMD_HWBP_HITS, (long)h, 0, 0, 0);
    if (r != 0 || h->hdr.node_total == 0) {
        printf("[-] no watchpoint node for 0x%llx (r=%ld)\n", (unsigned long long)addr, r);
        free(h);
        return;
    }

    uint32_t total_nodes = h->hdr.node_total;
    printf("[*] 0x%llx: %u node(s)\n", (unsigned long long)addr, total_nodes);

    for (uint32_t idx = 0; idx < total_nodes; idx++) {
        char lbl[300];
        memset(h, 0, sizeof(*h));
        h->hdr.watch_addr = addr;
        h->hdr.node_index = idx;
        if (sh_call(SH_CMD_HWBP_HITS, (long)h, 0, 0, 0) != 0) continue;
        if (h->hdr.hit_count == 0 && h->hdr.total == 0) continue;

        printf("\n=== node %u/%u tid=%u len=%u %s hits=%u ring=%u armed=%u max_hits=%u ===\n",
               idx + 1, total_nodes, h->hdr.tid, h->hdr.bp_len, watch_type_name(SH_WATCH_WRITE),
               h->hdr.hit_count, h->hdr.total, h->hdr.is_armed, h->hdr.max_hits);

        for (uint32_t i = 0; i < h->hdr.count; i++) {
            struct sh_hwbp_hit *e = &h->entries[i];
            printf("\n--- hit %u/%u  val=0x%llx ---\n", i + 1, h->hdr.count,
                   (unsigned long long)e->val);
            resolve_label(pid, e->pc, lbl, sizeof(lbl));
            printf("  pc  %s   (0x%llx)\n", lbl, (unsigned long long)e->pc);
            if (e->lr) {
                resolve_label(pid, e->lr, lbl, sizeof(lbl));
                printf("  lr  %s   (0x%llx)\n", lbl, (unsigned long long)e->lr);
            }
            printf("  sp  0x%llx\n", (unsigned long long)e->sp);
            for (int k = 0; k < 8; k++)
                printf("  x%d 0x%llx\n", k, (unsigned long long)e->x[k]);
            for (int k = 0; k < SH_HIT_ST_WORDS; k++) {
                uint64_t v = e->st[k];
                if (!v) continue;
                resolve_label(pid, v, lbl, sizeof(lbl));
                printf("  st[%d] (sp+%d) 0x%llx  %s\n", k, k * 8, (unsigned long long)v, lbl);
            }
        }

        if (h->hdr.stack_len) {
            printf("\n--- stack snapshot (sp, %u bytes) ---\n", h->hdr.stack_len);
            for (uint32_t off = 0; off + 8 <= h->hdr.stack_len; off += 8) {
                uint64_t v;
                memcpy(&v, &h->stack[off], 8);
                if ((v >> 40) == 0)
                    continue;   /* only plausible code/stack pointers are useful */
                resolve_label(pid, v, lbl, sizeof(lbl));
                if (strstr(lbl, "unmapped"))
                    continue;
                printf("  sp+0x%02x = 0x%llx  %s\n", off, (unsigned long long)v, lbl);
            }
        }
        fflush(stdout);
    }
    free(h);
}

static void usage(void) {
    printf("xiaojianbang_hook — Zero-trace stealth hook tool\n\n");
    printf("Usage:\n");
    printf("  xiaojianbang_hook --pid <pid> --so <name> --offset <hex>[,<hex>...] [options]\n\n");
    printf("Default: hook offset(s) on ALL threads + new threads, then live-trace.\n\n");
    printf("Options:\n");
    printf("  --offset H[,H..]   SO-relative offset(s), repeatable or comma-list\n");
    printf("  --dump-size N      Bytes to dump per pointer arg (default 80, max 128)\n");
    printf("  --no-dump          Show register values only, no memory dump\n");
    printf("  --once             Capture first hit then exit\n");
    printf("  --listen-ret       Also capture return value\n");
    printf("  --modify-arg N=VAL Override register XN with VAL on entry\n");
    printf("  --replace-ret VAL  Skip function, return VAL directly\n");
    printf("  --nth N            Capture the Nth hit (skip first N-1)\n");
    printf("  --query            One-shot query of current data, then exit\n");
    printf("  --unhook           Remove all HWBPs for the offset(s), then exit\n\n");
    printf("Data watchpoint mode (\"who writes this address?\"):\n");
    printf("  --watch <hexaddr>  Watch an absolute user VA (data, not code)\n");
    printf("    --len N          Watch width: 1/2/4/8 (default 8, addr must be N-aligned)\n");
    printf("    --rw             Watch reads+writes instead of writes only\n");
    printf("    --read           Watch reads only\n");
    printf("    --max-hits N     Auto-disable after N hits (default 64, 0 = no cap)\n");
    printf("    --stack N        Stack snapshot bytes per node (default 128, max 256)\n");
    printf("    --no-auto        Do not auto-arm on newly created threads\n");
    printf("  --hits <hexaddr>   Dump the hit ring (pc/lr/regs/stack) of a watch\n");
    printf("  --unwatch <hexaddr> Remove watchpoints at that address\n");
    printf("\n  ARM64 allows 4 watchpoint registers per thread; to cover 32 bytes use\n");
    printf("  four --watch calls at +0/+8/+16/+24 (run the tool per address).\n\n");
    printf("Examples:\n");
    printf("  xiaojianbang_hook --pid 5948 --so libwtf.so --offset 0x4161c\n");
    printf("  xiaojianbang_hook --pid 5948 --so libwtf.so --offset 0x41a90,0x41d7c --dump-size 64\n");
    printf("  xiaojianbang_hook --pid 5948 --so libwtf.so --offset 0x4161c --replace-ret 0x1234\n");
    printf("  xiaojianbang_hook --pid 5948 --watch 0x796614ba50 --len 8\n");
    printf("  xiaojianbang_hook --pid 5948 --hits 0x796614ba50\n");
    printf("  xiaojianbang_hook --pid 5948 --watch 0x796614ba50 --unwatch 0x796614ba50\n");
}

int main(int argc, char **argv)
{
    uint32_t pid = 0;
    const char *so_name = NULL;
    uint64_t offsets[MAX_OFFSETS];
    int offset_count = 0;
    int do_listen_ret = 0, do_unhook = 0, do_query = 0, do_once = 0;
    int do_replace_ret = 0, do_modify_arg = 0;
    uint64_t replace_ret_val = 0;
    uint64_t override_mask = 0;
    uint64_t override_args[8] = {0};
    uint32_t dump_size = 80;
    uint32_t nth_hit = 0;
    /* data watchpoint mode */
    uint64_t watch_addr = 0, hits_addr = 0, unwatch_addr = 0;
    uint32_t watch_len = 8, watch_type = SH_WATCH_WRITE;
    uint32_t max_hits = 64, stack_size = 128;
    int no_auto = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i+1 < argc) pid = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--so") && i+1 < argc) so_name = argv[++i];
        else if (!strcmp(argv[i], "--offset") && i+1 < argc) {
            char *arg = argv[++i];
            while (*arg && offset_count < MAX_OFFSETS) {
                offsets[offset_count++] = strtoull(arg, NULL, 0);
                char *comma = strchr(arg, ',');
                if (!comma) break;
                arg = comma + 1;
            }
        }
        else if (!strcmp(argv[i], "--listen-ret")) do_listen_ret = 1;
        else if (!strcmp(argv[i], "--unhook")) do_unhook = 1;
        else if (!strcmp(argv[i], "--query")) do_query = 1;
        else if (!strcmp(argv[i], "--once")) do_once = 1;
        else if (!strcmp(argv[i], "--no-dump")) dump_size = 0;
        else if (!strcmp(argv[i], "--dump-size") && i+1 < argc) {
            dump_size = (uint32_t)strtoul(argv[++i], NULL, 0);
            if (dump_size > SH_DUMP_MAX) dump_size = SH_DUMP_MAX;
        }
        else if (!strcmp(argv[i], "--replace-ret") && i+1 < argc) {
            do_replace_ret = 1;
            replace_ret_val = strtoull(argv[++i], NULL, 0);
        }
        else if (!strcmp(argv[i], "--modify-arg") && i+1 < argc) {
            char *arg = argv[++i];
            char *eq = strchr(arg, '=');
            if (!eq) { fprintf(stderr, "[-] --modify-arg format: N=VALUE\n"); return 1; }
            int idx = atoi(arg);
            if (idx < 0 || idx > 7) { fprintf(stderr, "[-] arg index must be 0-7\n"); return 1; }
            override_args[idx] = strtoull(eq + 1, NULL, 0);
            override_mask |= (1ULL << idx);
            do_modify_arg = 1;
        }
        else if (!strcmp(argv[i], "--nth") && i+1 < argc) {
            nth_hit = (uint32_t)strtoul(argv[++i], NULL, 0);
        }
        else if (!strcmp(argv[i], "--watch") && i+1 < argc) watch_addr = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--hits") && i+1 < argc) hits_addr = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--unwatch") && i+1 < argc) unwatch_addr = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--len") && i+1 < argc) watch_len = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--rw")) watch_type = SH_WATCH_RW;
        else if (!strcmp(argv[i], "--read")) watch_type = SH_WATCH_READ;
        else if (!strcmp(argv[i], "--write")) watch_type = SH_WATCH_WRITE;
        else if (!strcmp(argv[i], "--max-hits") && i+1 < argc) max_hits = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--stack") && i+1 < argc) stack_size = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--no-auto")) no_auto = 1;
    }

    /* ---- data watchpoint modes: no --so/--offset needed ---- */
    if (watch_addr || hits_addr || unwatch_addr) {
        if (!pid) { fprintf(stderr, "[-] --pid is required for watch modes\n"); return 1; }
        if (sh_call(SH_CMD_STATUS, 0, 0, 0, 0) != (long)(SH_STATUS_MAGIC + SH_VERSION_CODE)) {
            fprintf(stderr, "[-] KPM not active (or version mismatch; rebuild the tool)\n");
            return 1;
        }
        int handled = 0;
        if (unwatch_addr) { cmd_unwatch(pid, unwatch_addr); handled++; }
        if (watch_addr) {
            if (watch_len != 1 && watch_len != 2 && watch_len != 4 && watch_len != 8) {
                fprintf(stderr, "[-] --len must be 1/2/4/8\n"); return 1;
            }
            if (watch_addr & (uint64_t)(watch_len - 1)) {
                fprintf(stderr, "[-] 0x%llx not aligned to %u\n",
                        (unsigned long long)watch_addr, watch_len);
                return 1;
            }
            if (stack_size > SH_STACK_MAX) stack_size = SH_STACK_MAX;
            cmd_watch(pid, watch_addr, watch_len, watch_type, max_hits, stack_size, !no_auto);
            handled++;
        }
        if (hits_addr)
            cmd_hits(pid, hits_addr);
        (void)handled;
        return 0;
    }

    if (!pid || !so_name || offset_count == 0) { usage(); return 1; }

    /* ARM64 hardware limit: max 6 execution breakpoints per thread.
     * Each offset consumes one breakpoint slot on every thread, so hooking
     * more than 6 offsets at once will make later registrations fail (-ENOSPC). */
    if (offset_count > 6) {
        fprintf(stderr,
            "[!] WARNING: %d offsets requested, but ARM64 allows only 6 HW "
            "execution breakpoints per thread.\n"
            "[!]          Offsets beyond the 6th will fail to register (-ENOSPC).\n"
            "[!]          Reduce to <=6 offsets, or split across multiple runs.\n",
            offset_count);
    }

    if (sh_call(SH_CMD_STATUS, 0, 0, 0, 0) != (long)(SH_STATUS_MAGIC + SH_VERSION_CODE)) {
        fprintf(stderr, "[-] KPM not active\n"); return 1;
    }

    uint64_t so_base = resolve_so_base(pid, so_name);
    if (!so_base) { fprintf(stderr, "[-] %s not found in pid %u\n", so_name, pid); return 1; }

    uint64_t targets[MAX_OFFSETS];
    for (int k = 0; k < offset_count; k++)
        targets[k] = so_base + offsets[k];
    printf("[+] %s base=0x%llx, %d offset(s)\n", so_name,
           (unsigned long long)so_base, offset_count);

    uint32_t tids[MAX_TIDS];
    int tid_count = get_tids(pid, tids, MAX_TIDS);
    if (tid_count == 0) { fprintf(stderr, "[-] no threads for pid %u\n", pid); return 1; }

    /* ---- UNHOOK: remove every (offset x tid) node, then exit ---- */
    if (do_unhook) {
        int n = 0;
        for (int k = 0; k < offset_count; k++)
            for (int t = 0; t < tid_count; t++)
                if (sh_call(SH_CMD_HWBP_UNHOOK, (long)targets[k], (long)tids[t], 0, 0) == 0) n++;
        printf("[+] unhooked %d nodes (%d offsets x %d threads)\n", n, offset_count, tid_count);
        return 0;
    }

    /* ---- QUERY: one-shot dump of all matching nodes, then exit ---- */
    if (do_query) {
        for (int k = 0; k < offset_count; k++) {
            struct sh_hwbp_query q0 = {0};
            q0.target_addr = targets[k];
            q0.node_index = 0;
            if (sh_call(SH_CMD_HWBP_QUERY, (long)&q0, 0, 0, 0) != 0) continue;
            uint32_t total = q0.node_total;
            for (uint32_t idx = 0; idx < total; idx++) {
                struct sh_hwbp_query q = {0};
                q.target_addr = targets[k];
                q.node_index = idx;
                if (sh_call(SH_CMD_HWBP_QUERY, (long)&q, 0, 0, 0) != 0) continue;
                if (q.hit_count > 0)
                    print_hit(offsets[k], &q, do_listen_ret);
            }
        }
        return 0;
    }

    /* ---- SET HOOK on every thread + auto-register new threads ---- */
    uint32_t flags = SH_HWBP_FLAG_EXECUTE;
    if (do_listen_ret) flags |= SH_HWBP_FLAG_LISTEN_RET;

    int set_total = 0;
    for (int k = 0; k < offset_count; k++) {
        for (int t = 0; t < tid_count; t++) {
            struct sh_hwbp_request req = {0};
            req.target_addr = targets[k];
            req.target_pid = tids[t];
            req.flags = flags;
            req.dump_size = dump_size;
            if (sh_call(SH_CMD_HWBP_HOOK, (long)&req, 0, 0, 0) == 0) set_total++;
        }
        /* auto-register the same hook on threads spawned later */
        sh_call(SH_CMD_HWBP_AUTO_THREAD, (long)targets[k], (long)pid, 0, (long)flags);

        /* per-offset overrides / skip count */
        if (do_replace_ret || do_modify_arg) {
            struct sh_hwbp_override ov = {0};
            ov.target_addr = targets[k];
            ov.target_pid = pid;
            if (do_modify_arg) {
                ov.flags |= SH_HWBP_FLAG_MODIFY_ARGS;
                ov.override_mask = override_mask;
                for (int i = 0; i < 8; i++) ov.override_args[i] = override_args[i];
            }
            if (do_replace_ret) {
                ov.flags |= SH_HWBP_FLAG_SKIP_ORIGIN;
                ov.ret_value = replace_ret_val;
            }
            sh_call(SH_CMD_HWBP_SET_OVERRIDE, (long)&ov, 0, 0, 0);
        }
        if (nth_hit > 0)
            sh_call(SH_CMD_HWBP_SET_SKIP, (long)targets[k], (long)(nth_hit - 1), 0, 0);
    }
    printf("[+] HWBP set: %d nodes (%d offsets x %d threads), dump_size=%u, flags=0x%x\n",
           set_total, offset_count, tid_count, dump_size, flags);

    /* If only modifying args / replacing return, no need to live-trace */
    if (do_replace_ret || do_modify_arg) {
        printf("[+] override active; not entering trace loop\n");
        return 0;
    }

    /* ---- LIVE TRACE LOOP: poll every node, print new hits until Ctrl+C ---- */
    signal(SIGINT, on_sigint);
    printf("[*] live trace started, press Ctrl+C to stop & unhook...\n");
    fflush(stdout);

    while (g_running) {
        for (int k = 0; k < offset_count; k++) {
            struct sh_hwbp_query q0 = {0};
            q0.target_addr = targets[k];
            q0.node_index = 0;
            if (sh_call(SH_CMD_HWBP_QUERY, (long)&q0, 0, 0, 0) != 0) continue;
            uint32_t total = q0.node_total;
            for (uint32_t idx = 0; idx < total; idx++) {
                struct sh_hwbp_query q = {0};
                q.target_addr = targets[k];
                q.node_index = idx;
                if (sh_call(SH_CMD_HWBP_QUERY, (long)&q, 0, 0, 0) != 0) continue;
                if (q.hit_count == 0) continue;
                if (q.hit_count != seen_get(targets[k], q.tid)) {
                    seen_set(targets[k], q.tid, q.hit_count);
                    print_hit(offsets[k], &q, do_listen_ret);
                    if (do_once) { g_running = 0; break; }
                }
            }
            if (!g_running) break;
        }
        if (g_running) usleep(50000);  /* 50ms */
    }

    /* cleanup: unhook everything we set */
    printf("\n[*] stopping, unhooking...\n");
    int n = 0;
    for (int k = 0; k < offset_count; k++)
        for (int t = 0; t < tid_count; t++)
            if (sh_call(SH_CMD_HWBP_UNHOOK, (long)targets[k], (long)tids[t], 0, 0) == 0) n++;
    printf("[+] unhooked %d nodes\n", n);
    return 0;
}

