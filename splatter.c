// SPDX-License-Identifier: GPL-2.0

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/skbuff.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nf_conntrack_common.h>

#include <net/tcp.h>
#include <net/sock.h>
#include <net/netfilter/nf_conntrack.h>

#pragma GCC diagnostic error "-Wall"
#pragma GCC diagnostic error "-Wextra"
#pragma GCC diagnostic error "-Wshadow"
#pragma GCC diagnostic error "-Wconversion"
#pragma GCC diagnostic error "-Woverflow"
#pragma GCC diagnostic ignored "-Wsign-conversion"

static struct nf_hook_ops g_nf_hook_op;

#define CT_ALLOW_MARK 0x1

static inline
void set_ct_mark(struct nf_conn* ct, u32 mark)
{
#if defined(HAVE_NF_CT_SET_MARK) || defined(CONFIG_NF_CONNTRACK_MARK)
    /* Some kernels export nf_ct_set_mark(), but guarded by config;
       if not available, fall back to direct write under lock. */
    /* nf_ct_set_mark(ct, mark); */ /* Uncomment if available on your tree */
    spin_lock_bh(&ct->lock);
    ct->mark = mark;
    spin_unlock_bh(&ct->lock);
#else
    spin_lock_bh(&ct->lock);
    ct->mark = mark;
    spin_unlock_bh(&ct->lock);
#endif
}

static inline bool tcp_skb(const struct sk_buff* skb)
{
    return skb && ip_hdr(skb) && ip_hdr(skb)->protocol == IPPROTO_TCP;
}

static inline
bool socket_root_root(const struct sock *sk)
{
    /**
     * UID: available on struct sock.
     * GID: not cached on struct sock; try to fetch from file creds if present.
     * For retransmits we won't have sk_socket->file, but we only call this
     * on IP_CT_NEW where it's typically still available.
    **/
    kuid_t kuid = sk->sk_uid;
    if ( !uid_eq(kuid, GLOBAL_ROOT_UID) )
    {
        printk(KERN_ERR "VPR Splatter: UID %d denied.", kuid.val);
        return false;
    }

    if (sk->sk_socket && sk->sk_socket->file)
    {
        const struct cred* fcred = sk->sk_socket->file->f_cred;
        if ( !fcred )
        {
            return false;
        }

        return gid_eq(fcred->sgid, GLOBAL_ROOT_GID) ||
               gid_eq(fcred->egid, GLOBAL_ROOT_GID);
    }

    return false; /* If you want to *require* gid==0, be strict and fail when unavailable. */
}

static
unsigned int
nf_ipv4_hook_func(
    void*                       priv,
    struct sk_buff*             skb,
    const struct nf_hook_state* state
)
{
    (void)priv;
    (void)state;

    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;

    if (!tcp_skb(skb))
    {
        return NF_ACCEPT;
    }

    ct = nf_ct_get(skb, &ctinfo);
    if (ct)
    {
        /* Fast path for established/related: honor cached policy */
        if (ctinfo != IP_CT_NEW)
        {
            return (READ_ONCE(ct->mark) & CT_ALLOW_MARK) ? NF_ACCEPT : NF_DROP;
        }

        /* IP_CT_NEW: decide once and tag CT */
        if ( skb->sk )
        {
            struct sock *sk = skb_to_full_sk(skb);
            bool allow = false;

            if ( sk && (sk->sk_protocol == IPPROTO_TCP) )
            {
                rcu_read_lock(); /* sk->sk_socket->file->f_cred can be RCU protected */
                allow = socket_root_root(sk);
                rcu_read_unlock();
            }

            if ( allow ) /* Preserve any previous marks and set allow bit */
            {
                u32 old = READ_ONCE(ct->mark);
                set_ct_mark(ct, old | CT_ALLOW_MARK);
                // printk(KERN_INFO "VPR Splatter: Accepting TCP traffic"); // DEBUG
                return NF_ACCEPT;
            }
            else /* Explicitly clear allow for this flow */
            {
                u32 old = READ_ONCE(ct->mark);
                set_ct_mark(ct, old & (~CT_ALLOW_MARK));
                return NF_DROP;
            }
        }
        else /* New conn with no skb->sk? Play it safe: drop. */
        {
            
            return NF_DROP;
        }
    }

    return NF_DROP; /* No conntrack entry (nf_conntrack not loaded or disabled). */
}

static int __init _module_entry(void)
{
    g_nf_hook_op.hook     = nf_ipv4_hook_func;
    g_nf_hook_op.pf       = NFPROTO_IPV4;
    g_nf_hook_op.hooknum  = NF_INET_LOCAL_OUT;
    g_nf_hook_op.priority = NF_IP_PRI_FILTER;

    if (nf_register_net_hook(&init_net, &g_nf_hook_op))
    {
        pr_err("VPR Splatter: nf_register_net_hook failed\n");
        return -EINVAL;
    }

    pr_info("VPR Splatter: Init.\n");
    return 0;
}

static void __exit _module_exit(void)
{
    nf_unregister_net_hook(&init_net, &g_nf_hook_op);
    pr_info("splatter: Shutdown.\n");
}

module_init(_module_entry);
module_exit(_module_exit);

MODULE_AUTHOR("VPR");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
