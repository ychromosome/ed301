#ifndef ED301_V2_TLS_POLICY_H
#define ED301_V2_TLS_POLICY_H

/* Local integration policy from Martin's D2 decision. These are explicit
 * SSL_CTX_set1_groups_list/-groups values, not changes to libssl or the host.
 * Stock OpenSSL's DEFAULT pseudo-group remains its own built-in list.
 * Raw X301 must never be added here as a fallback. */
#define X301_V2_DEFAULT_GROUPS "X301MLKEM1024"
#define X301_V2_RAW_TEST_GROUP "X301"

#endif
