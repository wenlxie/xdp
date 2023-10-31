#include <linux/bpf.h>
#include "hook.h"
/*
 * Comments from Linux Kernel:
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader.
 * End of comments
 * You can either use the helper header file below
 * so that you don't need to define it yourself:
 * #include <bpf/bpf_helpers.h>
 */
#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def {
      unsigned int type;
      unsigned int key_size;
      unsigned int value_size;
      unsigned int max_entries;
      unsigned int flags;
};

SEC("maps")
struct bpf_map_def  xdpcap_fexit_hook = XDPCAP_HOOK();

SEC("maps")
struct bpf_map_def  xdpcap_fentry_hook = XDPCAP_HOOK();

SEC("xdp")
int prog_xdp_fentry(struct xdp_md *ctx) {
      return xdpcap_exit(ctx, &xdpcap_fentry_hook, XDP_PASS);
}

SEC("xdp")
int prog_xdp_exit_redirect(struct xdp_md *ctx) {
      return xdpcap_exit(ctx, &xdpcap_fexit_hook, XDP_REDIRECT);
}

SEC("xdp")
int prog_xdp_exit_drop(struct xdp_md *ctx) {
      return xdpcap_exit(ctx, &xdpcap_fexit_hook, XDP_DROP);
}

SEC("xdp")
int prog_xdp_exit_pass(struct xdp_md *ctx) {
      return xdpcap_exit(ctx, &xdpcap_fexit_hook, XDP_PASS);
}

SEC("xdp")
int prog_xdp_exit_tx(struct xdp_md *ctx) {
      return xdpcap_exit(ctx, &xdpcap_fexit_hook, XDP_TX);
}

SEC("xdp")
int prog_xdp_exit_aborted(struct xdp_md *ctx) {
      return xdpcap_exit(ctx, &xdpcap_fexit_hook, XDP_ABORTED);
}

char _license[] SEC("license") = "GPL";
