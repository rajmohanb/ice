/*******************************************************************************
*                                                                              *
*               Copyright (C) 2009-2012, MindBricks Technologies               *
*                   MindBricks Confidential Proprietary.                       *
*                         All Rights Reserved.                                 *
*                                                                              *
********************************************************************************
*                                                                              *
* This document contains information that is confidential and proprietary to   *
* MindBricks Technologies. No part of this document may be reproduced in any   *
* form whatsoever without prior written approval from MindBricks Technologies. *
*                                                                              *
*******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/


#include "stun_base.h"
#include "ice_api.h"
#include "ice_int.h"
#include "ice_addr_sel.h"


#define RFC3484_DEFAULT_POLICY_TBL_SIZE     5
#define RFC3484_DEF_PRECEDENCE              0
#define RFC3484_DEF_LABEL                   5


typedef struct
{
    struct in6_addr prefix;         /** Perfix */
    uint32_t        prefix_len;     /** Prefix length in bits */
    int32_t         precedence;     /** Precedence */
    int32_t         label;          /** Label */
} rfc3484_addr_sel_rule_t;



/**
 * The default policy table as specified in rfc 3484
 */
static rfc3484_addr_sel_rule_t def_policy_table[RFC3484_DEFAULT_POLICY_TBL_SIZE] =
{
    {
        { .s6_addr = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
        }, 128, 50, 0
    },
    {
        { .s6_addr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        }, 0, 40, 1
    },
    {
        { .s6_addr = { 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        }, 16, 30, 2
    },
    {
        { .s6_addr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        }, 96, 20, 3
    },
    {
        { .s6_addr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
        }, 96, 10, 4
    }
};



static int32_t rfc3484_get_common_matching_prefix(ice_rfc3484_addr_pair_t *pair)
{
    int32_t i, bits = 0;
    struct in6_addr ipv6_src, ipv6_dst;

    if (inet_pton(AF_INET6, (char *)pair->dest->ip_addr, &ipv6_dst) != 1) 
        return 0;
    if (inet_pton(AF_INET6, (char *)pair->src->ip_addr, &ipv6_src) != 1) 
        return 0;

    for (i = 0; i < 4; i++)
    {
        if (ipv6_src.s6_addr32[i] != ipv6_dst.s6_addr32[i]) break;
        bits += 32;
    }

    if (i < 4)
    {
        /** the source and dest addresses do not match */
        uint32_t j, mask;
        uint32_t res = ipv6_src.s6_addr32[i] ^ ipv6_dst.s6_addr32[i];

        mask = 1;
        mask = 1 << 31;
        for (j = 0; j < 32; j++)
        {
            if ((res & mask) != 0) break;
            
            mask = mask >> 1;
            ++bits;
        }
    }

    return bits;
}


static int32_t rfc3484_get_precedence(ice_transport_t *addr)
{
    uint32_t i;
    struct in6_addr ipv6;

    if (addr->type != STUN_INET_ADDR_IPV6) return 0;
    if (inet_pton(AF_INET6, (char *)addr->ip_addr, &ipv6) != 1) return 0;

    for (i = 0; i < RFC3484_DEFAULT_POLICY_TBL_SIZE; i++)
    {
        uint32_t bits = def_policy_table[i].prefix_len;
        uint8_t *mask = def_policy_table[i].prefix.s6_addr;
        uint8_t *val = ipv6.s6_addr;

        while (bits >= 8)
        {
            if (*mask != *val) break;

            ++mask;
            ++val;
            bits -= 8;
        }

        if (bits < 8)
        {
            if ((*mask & (0xff00 >> bits)) == (*val & (0xff00 >> bits)))
                break;
        }
    }

    if (i >= RFC3484_DEFAULT_POLICY_TBL_SIZE)
        return RFC3484_DEF_PRECEDENCE;
    else
        return def_policy_table[i].precedence;
}



static int32_t rfc3484_get_label(ice_transport_t *addr)
{
    uint32_t i;
    struct in6_addr ipv6;

    if (addr->type != STUN_INET_ADDR_IPV6) return 0;
    if (inet_pton(AF_INET6, (char *)addr->ip_addr, &ipv6) != 1) return 0;

    for (i = 0; i < RFC3484_DEFAULT_POLICY_TBL_SIZE; i++)
    {
        uint32_t bits = def_policy_table[i].prefix_len;
        uint8_t *mask = def_policy_table[i].prefix.s6_addr;
        uint8_t *val = ipv6.s6_addr;

        while (bits >= 8)
        {
            if (*mask != *val) break;

            ++mask;
            ++val;
            bits -= 8;
        }

        if (bits < 8)
        {
            if ((*mask & (0xff00 >> bits)) == (*val & (0xff00 >> bits)))
                break;
        }
    }

    if (i >= RFC3484_DEFAULT_POLICY_TBL_SIZE)
        return RFC3484_DEF_LABEL;
    else
        return def_policy_table[i].label;
}



static int32_t rfc3484_get_scope(ice_transport_t *addr)
{
    int32_t scope = 0;

    if (addr->type == STUN_INET_ADDR_IPV6)
    {
        struct in6_addr ipv6;

        if (inet_pton(AF_INET6, (char *)addr->ip_addr, &ipv6) != 1)
            goto scope_end;

        /** RFC 3484 Sec 3.1 Scope Comparisions */ 
        if (IN6_IS_ADDR_MULTICAST(&ipv6))
        {
            /**
             * Multicase destination addresses have a 4-bit scope field that 
             * controls the propagation of the multicast packet - rfc 2373.
             *
             * |-------------------------------------------------------------|
             * | 8 bits  | 4 bits | 4 bits |           128 bits              |
             * |-------------------------------------------------------------|
             * |1111 1111| Flags  | scope  |           Group ID              |
             * |-------------------------------------------------------------|
             */
            scope = ipv6.s6_addr[1] & 0xf;
        }
        else if (IN6_IS_ADDR_LOOPBACK(&ipv6))
        {
            /** 
             * RFC3484 - Sec 3.4 
             * The loopback address should be treated as having link-local scope
             */
            scope = 2;
        }
        else if (IN6_IS_ADDR_LINKLOCAL(&ipv6))
        {
            scope = 2;
        }
        else if (IN6_IS_ADDR_SITELOCAL(&ipv6))
        {
            scope = 5;
        }
        else
        {
            /** treat everything else as global */
            scope = 14;
        }
    }
    else if (addr->type == STUN_INET_ADDR_IPV4)
    {
        /**
         * As per ICE spec, an ice lite client uses the rfc3484 mechanism to
         * choose a default destination address only when there are multiple
         * IPv6 addresses to choose from. Hence IPv4 address is not handled.
         */
        scope = 0;
    }

scope_end:
    return scope;
}



static int32_t rfc3484_cmp_addr(const void *p1, const void *p2)
{
    int32_t addr1_src_scope, addr1_dst_scope, addr1_src_label, addr1_dst_label;
    int32_t addr2_src_scope, addr2_dst_scope, addr2_src_label, addr2_dst_label;
    int32_t addr1_prec, addr2_prec;
    ice_rfc3484_addr_pair_t *addr1 = (ice_rfc3484_addr_pair_t *)p1;
    ice_rfc3484_addr_pair_t *addr2 = (ice_rfc3484_addr_pair_t *)p2;

    /**
     * RFC 3484 Sec 6. Destination Address Selection
     * The destination address selection algorithm takes a list of
     * destination addresses and sorts the addresses to produce a new list.
     */

    /** Rule 1:  Avoid unusable destinations */
    if ((addr1->reachable == true) && (addr2->reachable == false))
        return -1;

    if ((addr1->reachable == false) && (addr2->reachable == true))
        return 1;

    /** 
     * The ice stack application might not want to implement the functionality
     * of determining whether a destination address is reachable or not, in 
     * which case both the destination addresses will be unreachable at this 
     * point. In such a situation, apply other available rules to sort them.
     */

    /** Rule 2:  Prefer matching scope */
    addr1_src_scope = rfc3484_get_scope(addr1->src);
    addr1_dst_scope = rfc3484_get_scope(addr1->dest);
    addr2_src_scope = rfc3484_get_scope(addr2->src);
    addr2_dst_scope = rfc3484_get_scope(addr2->dest);

    if ((addr1_dst_scope == addr1_src_scope) && 
            (addr2_dst_scope != addr2_src_scope))
        return -1;

    if ((addr1_dst_scope != addr1_src_scope) &&
            (addr2_dst_scope == addr2_src_scope))
        return 1;

    /** Rule 3:  Avoid deprecated addresses */
    /** no information as to whether an address is deprecated or not */

    /** Rule 4:  Prefer home addresses */
    /** 
     * no information as to whether an address is home address or 
     * care-of address. This is applicable more for a mobile node.
     */

    /** Rule 5:  Prefer matching label */
    addr1_src_label = rfc3484_get_label(addr1->src);
    addr1_dst_label = rfc3484_get_label(addr1->dest);
    addr2_src_label = rfc3484_get_label(addr2->src);
    addr2_dst_label = rfc3484_get_label(addr2->dest);

    if ((addr1_dst_label == addr1_src_label) && 
            (addr2_dst_label != addr2_src_label))
        return -1;

    if ((addr1_dst_label != addr1_src_label) &&
            (addr2_dst_label == addr2_src_label))
        return 1;

    /** Rule 6:  Prefer higher precedence */
    addr1_prec = rfc3484_get_precedence(addr1->dest);
    addr2_prec = rfc3484_get_precedence(addr2->dest);

    if (addr1_prec > addr2_prec)
        return -1;

    if (addr1_prec < addr2_prec)
        return 1;

    /** Rule 7:  Prefer native transport */
    /** no information on whether the given address is native or encapsulated */

    /** Rule 8:  Prefer smaller scope */
    if (addr1_dst_scope < addr2_dst_scope)
        return -1;

    if (addr1_dst_scope > addr2_dst_scope)
        return 1;

    /** Rule 9:  Use longest matching prefix */
    if (addr1->dest->type == addr2->dest->type)
    {
        int32_t addr1_match_bits, addr2_match_bits;

        addr1_match_bits = rfc3484_get_common_matching_prefix(addr1);
        addr2_match_bits = rfc3484_get_common_matching_prefix(addr2);

        if (addr1_match_bits > addr2_match_bits)
            return -1;

        if (addr1_match_bits < addr2_match_bits)
            return 1;
    }

    /** Rule 10:  Otherwise, leave the order unchanged */

    return 0;
}


int32_t ice_addr_sel_determine_destination_address(
                    ice_rfc3484_addr_pair_t *addr_list, int32_t num)
{
    qsort(addr_list, num, 
            sizeof(ice_rfc3484_addr_pair_t), rfc3484_cmp_addr);

    return STUN_OK;
}


/******************************************************************************/

#ifdef __cplusplus
}
#endif

/******************************************************************************/
