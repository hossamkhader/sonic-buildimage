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

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#include "ipv6_profile.h"

static uint8_t pac_ipv6_value_width(pac_ipv6_property_type_t type)
{
    switch (type)
    {
        case PAC_IPV6_PROPERTY_LITERAL: return 32;
        case PAC_IPV6_PROPERTY_TENANT_ID:
        case PAC_IPV6_PROPERTY_PORT_ID: return 64;
        default: return 0;
    }
}

static int pac_ipv6_property_value(const pac_ipv6_profile_property_t *property,
                                   uint64_t tenant_id,
                                   uint64_t port_id,
                                   uint64_t *value)
{
    switch (property->type)
    {
        case PAC_IPV6_PROPERTY_LITERAL:
            *value = property->value;
            break;
        case PAC_IPV6_PROPERTY_TENANT_ID:
            *value = tenant_id;
            break;
        case PAC_IPV6_PROPERTY_PORT_ID:
            *value = port_id;
            break;
        default:
            return -1;
    }

    if (pac_ipv6_value_width(property->type) == 0 ||
        (property->type == PAC_IPV6_PROPERTY_LITERAL && *value > UINT32_MAX) ||
        (property->length < 64 && (*value >> property->length) != 0))
    {
        return -1;
    }
    return 0;
}

static int pac_ipv6_profile_validate(const pac_ipv6_profile_t *profile)
{
    uint8_t occupied[128] = {0};
    size_t i;
    size_t summarize_count = 0;

    if (profile == NULL || profile->property_count == 0 ||
        profile->property_count > PAC_IPV6_PROFILE_MAX_PROPERTIES)
    {
        return -1;
    }

    for (i = 0; i < profile->property_count; ++i)
    {
        const pac_ipv6_profile_property_t *property = &profile->properties[i];
        uint16_t end = (uint16_t)property->offset + property->length;
        uint16_t bit;
        uint8_t width;

        width = pac_ipv6_value_width(property->type);
        if (width == 0 || property->length == 0 || end > 128 ||
            property->length > width ||
            (property->type == PAC_IPV6_PROPERTY_LITERAL &&
             (property->length > 32 || property->value > UINT32_MAX)) ||
            property->isolation > 1 || property->summarize > 1)
        {
            return -1;
        }

        summarize_count += property->summarize;
        if (summarize_count > 1)
        {
            return -1;
        }

        for (bit = property->offset; bit < end; ++bit)
        {
            if (occupied[bit] != 0)
            {
                return -1;
            }
            occupied[bit] = 1;
        }
    }
    return 0;
}

int pac_ipv6_profile_auto_port_id(const char *interface_name, uint64_t *port_id)
{
    static const char prefix[] = "Ethernet";
    const char *digits;
    uint64_t value = 0;

    if (interface_name == NULL || port_id == NULL ||
        strncmp(interface_name, prefix, sizeof(prefix) - 1) != 0)
    {
        return -1;
    }

    digits = interface_name + sizeof(prefix) - 1;
    if (*digits == '\0' || (digits[0] == '0' && digits[1] != '\0'))
    {
        return -1;
    }
    for (; *digits != '\0'; ++digits)
    {
        if (*digits < '0' || *digits > '9' || value > (UINT64_MAX - 9) / 10)
        {
            return -1;
        }
        value = value * 10 + (uint64_t)(*digits - '0');
    }

    *port_id = value;
    return 0;
}

int pac_ipv6_profile_build_address(const pac_ipv6_profile_t *profile,
                                   uint64_t tenant_id,
                                   uint64_t port_id,
                                   char *address,
                                   size_t address_size)
{
    struct in6_addr assembled = IN6ADDR_ANY_INIT;
    size_t i;

    if (address == NULL || address_size < PAC_IPV6_ADDRESS_TEXT_LEN ||
        pac_ipv6_profile_validate(profile) != 0)
    {
        return -1;
    }

    for (i = 0; i < profile->property_count; ++i)
    {
        const pac_ipv6_profile_property_t *property = &profile->properties[i];
        uint64_t value;
        uint8_t bit;

        if (pac_ipv6_property_value(property, tenant_id, port_id, &value) != 0)
        {
            return -1;
        }

        for (bit = 0; bit < property->length; ++bit)
        {
            uint8_t source_bit = (uint8_t)(property->length - bit - 1);
            uint8_t target_bit = (uint8_t)(property->offset + bit);

            if ((value >> source_bit) & 1U)
            {
                assembled.s6_addr[target_bit / 8] |=
                    (uint8_t)(1U << (7U - (target_bit % 8U)));
            }
        }
    }

    if (IN6_IS_ADDR_UNSPECIFIED(&assembled) ||
        IN6_IS_ADDR_MULTICAST(&assembled) ||
        IN6_IS_ADDR_LINKLOCAL(&assembled))
    {
        return -1;
    }

    return inet_ntop(AF_INET6, &assembled, address, address_size) == NULL ? -1 : 0;
}
