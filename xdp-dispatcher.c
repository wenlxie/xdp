/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


/* The volatile return value prevents the compiler from assuming it knows the
 * return value and optimising based on that.
 */


__attribute__ ((noinline))
int dispatch_prog_xdp_fentry(struct xdp_md *ctx) {
        volatile int ret = XDP_PASS;
        if (!ctx)
          return XDP_ABORTED;
        return ret;
}


__attribute__ ((noinline))
int dispatch_prog_xdp_exit_pass(struct xdp_md *ctx) {
        volatile int ret = XDP_PASS;
        if (!ctx)
          return XDP_ABORTED;
        return ret;
}

__attribute__ ((noinline))
int dispatch_prog_xdp_exit_drop(struct xdp_md *ctx) {
        volatile int ret = XDP_PASS;
        if (!ctx)
          return XDP_ABORTED;
        return ret;
}

__attribute__ ((noinline))
int dispatch_prog_xdp_exit_tx(struct xdp_md *ctx) {
        volatile int ret = XDP_PASS;
        if (!ctx)
          return XDP_ABORTED;
        return ret;
}
__attribute__ ((noinline))
int dispatch_prog_xdp_exit_aborted(struct xdp_md *ctx) {
        volatile int ret = XDP_PASS;
        if (!ctx)
          return XDP_ABORTED;
        return ret;
}
__attribute__ ((noinline))
int dispatch_prog_xdp_exit_redirect(struct xdp_md *ctx) {
        volatile int ret = XDP_PASS;
        if (!ctx)
          return XDP_ABORTED;
        return ret;
}

__attribute__ ((noinline))
int cil_xdp_entry(struct xdp_md *ctx) {
        volatile int ret = XDP_PASS;
        if (!ctx)
          return XDP_ABORTED;
        return ret;
}


SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx)
{
        int ret;

        dispatch_prog_xdp_fentry(ctx);

        ret = cil_xdp_entry(ctx);

        switch (ret) {
         case XDP_PASS:
              return dispatch_prog_xdp_exit_pass(ctx);
         case XDP_REDIRECT:
              return dispatch_prog_xdp_exit_redirect(ctx);
         case XDP_DROP:
              return dispatch_prog_xdp_exit_drop(ctx);
         case XDP_TX:
              return dispatch_prog_xdp_exit_tx(ctx);
         default:
              return dispatch_prog_xdp_exit_aborted(ctx);

        }
        return ret;
}



char _license[] SEC("license") = "GPL";
