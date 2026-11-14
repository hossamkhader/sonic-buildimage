/*
 * Copyright 2026 SONiC Contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SONIC_PAC_IPV6_PROFILE_H
#define SONIC_PAC_IPV6_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PAC_IPV6_PROFILE_MAX_PROPERTIES 16
#define PAC_IPV6_ADDRESS_TEXT_LEN 46

typedef enum
{
    PAC_IPV6_PROPERTY_LITERAL = 0,
    PAC_IPV6_PROPERTY_TENANT_ID,
    PAC_IPV6_PROPERTY_PORT_ID
} pac_ipv6_property_type_t;

typedef struct
{
    uint8_t offset;
    uint8_t length;
    pac_ipv6_property_type_t type;
    uint64_t value;
    uint8_t isolation;
    uint8_t summarize;
} pac_ipv6_profile_property_t;

typedef struct
{
    size_t property_count;
    pac_ipv6_profile_property_t properties[PAC_IPV6_PROFILE_MAX_PROPERTIES];
} pac_ipv6_profile_t;

/*
 * Assemble an IPv6 address from profile bit properties. Bit offsets are
 * measured from the most significant bit of the 128-bit address. Literal
 * values are limited to 32 bits (matching the documented Cumulus behavior);
 * tenant and port identifiers may use up to 64 bits. With port_id_auto set,
 * the low-order property->length bits of the port's system MAC address are
 * used as the port ID; port_mac is required when the profile has a port-ID
 * property.
 *
 * Returns 0 on success and -1 for malformed profiles or values that do not
 * fit their configured property. port_id_auto must be 0 or 1.
 */
int pac_ipv6_profile_build_address(const pac_ipv6_profile_t *profile,
                                   uint64_t tenant_id,
                                   uint64_t port_id,
                                   const uint8_t port_mac[6],
                                   int port_id_auto,
                                   char *address,
                                   size_t address_size);

/* Convenience entry point that reads the interface's system MAC for auto mode. */
int pac_ipv6_profile_build_interface_address(const pac_ipv6_profile_t *profile,
                                            uint64_t tenant_id,
                                            uint64_t port_id,
                                            const char *interface_name,
                                            int port_id_auto,
                                            char *address,
                                            size_t address_size);

#ifdef __cplusplus
}
#endif

#endif
