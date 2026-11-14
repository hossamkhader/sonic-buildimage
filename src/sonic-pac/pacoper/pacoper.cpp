/*
 * Copyright 2021 Broadcom Inc.
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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <map>
#include <algorithm>
#include <set>
#include <unistd.h>
#include <netlink/netlink.h>
#include <linux/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include "ipv6_profile.h"
#include "pacoper.h"
#include "pacoper_common.h"
#include "nimapi.h"
#include "resources.h"

std::vector<std::string> authMgrMethod {"none", "802.1x", "mab"};

std::vector<std::string> userMgrAuthMethod {"undefined", "local", 
                                            "none", "radius"};
                                            
std::vector<std::string> authMgrPortStatus {"na", "authorized", "unauthorized"};

std::vector<std::string> vlanType {"Unassigned", "RADIUS",
                                   "Default", "Blocked"};

FpDbAdapter::FpDbAdapter( DBConnector *stateDb, DBConnector *configDb, DBConnector *appDb) :
                                    m_PacGlobalOperTbl(stateDb, STATE_PAC_GLOBAL_OPER_TABLE),
                                    m_PacPortOperTbl(stateDb, STATE_PAC_PORT_OPER_TABLE),
                                    m_PacAuthClientOperTbl(stateDb, STATE_PAC_AUTHENTICATED_CLIENT_OPER_TABLE),
                                    m_PacIpv6ProfileTbl(configDb, "PAC_IPV6_PROFILE"),
                                    m_PacIpv6ProfilePropertyTbl(configDb, "PAC_IPV6_PROFILE_PROPERTY"),
                                    m_PacPortIpv6ProfileTbl(configDb, "PAC_PORT_IPV6_PROFILE"),
                                    m_ConfigStaticRouteTbl(configDb, "STATIC_ROUTE"),
                                    m_PacRuntimeAclTableType(appDb, APP_ACL_TABLE_TYPE_TABLE_NAME),
                                    m_PacRuntimeAclTable(appDb, APP_ACL_TABLE_TABLE_NAME),
                                    m_PacRuntimeAclRuleTable(appDb, APP_ACL_RULE_TABLE_NAME),
                                    m_PacRuntimeStaticRouteTable(appDb, "STATIC_ROUTE"),
                                    m_PacIpv6RouteSummaryOperTbl(stateDb, "PAC_IPV6_ROUTE_SUMMARY"),
                                    m_AclTableState(stateDb, STATE_ACL_TABLE_TABLE_NAME),
                                    m_AclRuleState(stateDb, STATE_ACL_RULE_TABLE_NAME)
{
}

DBConnector *stateDb = new DBConnector("STATE_DB", 0);
DBConnector *configDb = new DBConnector("CONFIG_DB", 0);
DBConnector *appDb = new DBConnector("APPL_DB", 0);
FpDbAdapter * Fp = new FpDbAdapter(stateDb, configDb, appDb);

static bool pacParseUnsigned(const string &text, uint64_t &value)
{
  char *end = NULL;
  unsigned long long parsed;
  if (text.empty() || text[0] == '-' || text[0] == '+')
    return false;
  errno = 0;
  parsed = strtoull(text.c_str(), &end, 0);
  if (errno != 0 || end == text.c_str() || *end != '\0')
    return false;
  value = static_cast<uint64_t>(parsed);
  return true;
}

static bool pacIpv6AddressBuild(const string &interfaceName,
                                const pac_authenticated_clients_oper_table_t *client,
                                string &profileName, string &address,
                                string &isolationId, string &isolationMask)
{
  vector<FieldValueTuple> associationFields;
  vector<FieldValueTuple> profileFields;
  vector<string> propertyKeys;
  string portIdText = "auto";
  uint64_t portId = 0;
  bool portIdAuto = true;
  pac_ipv6_profile_t profile = {};

  if (client == NULL || !client->tenantIdPresent ||
      !Fp->m_PacPortIpv6ProfileTbl.get(interfaceName, associationFields))
    return false;

  for (const auto &entry : associationFields)
  {
    if (fvField(entry) == "profile")
      profileName = fvValue(entry);
    else if (fvField(entry) == "port_id")
      portIdText = fvValue(entry);
  }
  if (profileName.empty() || !Fp->m_PacIpv6ProfileTbl.get(profileName, profileFields))
    return false;

  if (portIdText != "auto")
  {
    if (!pacParseUnsigned(portIdText, portId))
      return false;
    portIdAuto = false;
  }

  Fp->m_PacIpv6ProfilePropertyTbl.getKeys(propertyKeys);
  for (const auto &key : propertyKeys)
  {
    vector<FieldValueTuple> propertyFields;
    if (key.compare(0, profileName.size() + 1, profileName + "|") != 0)
      continue;
    if (profile.property_count >= PAC_IPV6_PROFILE_MAX_PROPERTIES ||
        !Fp->m_PacIpv6ProfilePropertyTbl.get(key, propertyFields))
      return false;

    pac_ipv6_profile_property_t property = {};
    bool haveType = false, haveOffset = false, haveLength = false;
    string valueText;
    for (const auto &entry : propertyFields)
    {
      const string field = fvField(entry);
      const string value = fvValue(entry);
      uint64_t parsed;
      if (field == "type")
      {
        if (value == "literal") property.type = PAC_IPV6_PROPERTY_LITERAL;
        else if (value == "tenant-id") property.type = PAC_IPV6_PROPERTY_TENANT_ID;
        else if (value == "port-id") property.type = PAC_IPV6_PROPERTY_PORT_ID;
        else return false;
        haveType = true;
      }
      else if (field == "offset" || field == "length")
      {
        if (!pacParseUnsigned(value, parsed) || parsed > 255)
          return false;
        if (field == "offset") { property.offset = static_cast<uint8_t>(parsed); haveOffset = true; }
        else { property.length = static_cast<uint8_t>(parsed); haveLength = true; }
      }
      else if (field == "value")
      {
        valueText = value;
      }
      else if (field == "isolation" || field == "summarize")
      {
        bool enabled;
        if (value == "true" || value == "1") enabled = true;
        else if (value == "false" || value == "0") enabled = false;
        else return false;
        if (field == "isolation") property.isolation = enabled;
        else property.summarize = enabled;
      }
    }
    if (!haveType || !haveOffset || !haveLength)
      return false;
    if (property.type == PAC_IPV6_PROPERTY_LITERAL &&
        !pacParseUnsigned(valueText, property.value))
      return false;
    profile.properties[profile.property_count++] = property;
  }

  if (profile.property_count == 0)
    return false;

  char text[PAC_IPV6_ADDRESS_TEXT_LEN];
  int rc = pac_ipv6_profile_build_interface_address(
      &profile, client->tenantId, portId, interfaceName.c_str(), portIdAuto,
      text, sizeof(text));
  if (rc != 0)
    return false;

  struct in6_addr addressBytes;
  struct in6_addr maskBytes = {};
  struct in6_addr groupBytes;
  bool hasIsolationBits = false;
  bool hasTenantProperty = false;
  for (size_t i = 0; i < profile.property_count; ++i)
  {
    const auto &property = profile.properties[i];
    hasTenantProperty |= property.type == PAC_IPV6_PROPERTY_TENANT_ID;
    hasIsolationBits |= property.isolation != 0;
  }
  if (!hasIsolationBits && !hasTenantProperty)
    return false;
  if (inet_pton(AF_INET6, text, &addressBytes) != 1)
    return false;

  for (size_t i = 0; i < profile.property_count; ++i)
  {
    const auto &property = profile.properties[i];
    const bool include = hasIsolationBits ? property.isolation != 0 :
                         property.type == PAC_IPV6_PROPERTY_TENANT_ID;
    if (!include) continue;
    for (uint16_t bit = property.offset;
         bit < static_cast<uint16_t>(property.offset + property.length); ++bit)
      maskBytes.s6_addr[bit / 8] |= static_cast<uint8_t>(1U << (7U - (bit % 8U)));
  }

  for (size_t i = 0; i < sizeof(groupBytes.s6_addr); ++i)
    groupBytes.s6_addr[i] = addressBytes.s6_addr[i] & maskBytes.s6_addr[i];
  char maskText[PAC_IPV6_ADDRESS_TEXT_LEN];
  char groupText[PAC_IPV6_ADDRESS_TEXT_LEN];
  if (inet_ntop(AF_INET6, &maskBytes, maskText, sizeof(maskText)) == NULL ||
      inet_ntop(AF_INET6, &groupBytes, groupText, sizeof(groupText)) == NULL)
    return false;

  address = text;
  isolationId = groupText;
  isolationMask = maskText;
  return true;
}

struct PacIpv6Session
{
  string key;
  string interfaceName;
  string mac;
  string address;
  string profile;
  string isolationId;
  string isolationMask;
};

static bool pacStateField(Table &table, const string &key,
                          const string &field, string &value)
{
  vector<FieldValueTuple> fields;
  if (!table.get(key, fields)) return false;
  for (const auto &entry : fields)
  {
    if (fvField(entry) == field) { value = fvValue(entry); return true; }
  }
  return false;
}

static bool pacAclWait(Table &stateTable, const string &key)
{
  for (unsigned int i = 0; i < 500; ++i)
  {
    string status;
    if (pacStateField(stateTable, key, "status", status) && status == "Active")
      return true;
    usleep(10000);
  }
  return false;
}

static string pacAclTableName(const string &interfaceName, const string &stage)
{
  string name = "PAC6_" + stage + "_";
  for (char ch : interfaceName)
    name += ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
             (ch >= '0' && ch <= '9')) ? ch : '_';
  return name;
}

static bool pacIpv6AddressChange(const string &interfaceName,
                                 const string &address, bool add)
{
  struct nl_sock *sock = nl_socket_alloc();
  struct rtnl_link *link = NULL;
  struct rtnl_addr *addr = NULL;
  struct nl_addr *local = NULL;
  bool ok = false;

  if (sock == NULL || nl_connect(sock, NETLINK_ROUTE) < 0 ||
      rtnl_link_get_kernel(sock, 0, interfaceName.c_str(), &link) < 0)
    goto done;
  if (nl_addr_parse(address.c_str(), AF_INET6, &local) < 0)
    goto done;
  addr = rtnl_addr_alloc();
  if (addr == NULL)
    goto done;
  rtnl_addr_set_local(addr, local);
  rtnl_addr_set_prefixlen(addr, 128);
  rtnl_addr_set_ifindex(addr, rtnl_link_get_ifindex(link));
  ok = add ? rtnl_addr_add(sock, addr, NLM_F_CREATE | NLM_F_REPLACE) >= 0
           : rtnl_addr_delete(sock, addr, 0) >= 0;

done:
  if (addr) rtnl_addr_put(addr);
  if (local) nl_addr_put(local);
  if (link) rtnl_link_put(link);
  if (sock) nl_socket_free(sock);
  return ok;
}

static vector<PacIpv6Session> pacActiveIpv6Sessions(const string &excludedKey,
                                                     const PacIpv6Session *pending)
{
  vector<PacIpv6Session> sessions;
  vector<string> keys;
  Fp->m_PacAuthClientOperTbl.getKeys(keys);
  for (const auto &key : keys)
  {
    if (key == excludedKey) continue;
    size_t separator = key.find('|');
    if (separator == string::npos) continue;
    PacIpv6Session session;
    if (!pacStateField(Fp->m_PacAuthClientOperTbl, key, "ipv6_address", session.address) ||
        session.address.empty() ||
        !pacStateField(Fp->m_PacAuthClientOperTbl, key, "ipv6_profile", session.profile) ||
        session.profile.empty() ||
        !pacStateField(Fp->m_PacAuthClientOperTbl, key, "isolation_id", session.isolationId) ||
        !pacStateField(Fp->m_PacAuthClientOperTbl, key, "isolation_mask", session.isolationMask))
      continue;
    session.key = key;
    session.interfaceName = key.substr(0, separator);
    session.mac = key.substr(separator + 1);
    sessions.push_back(session);
  }
  if (pending) sessions.push_back(*pending);
  return sessions;
}

static string pacSafeRulePart(const string &text)
{
  string value;
  for (char ch : text)
    value += ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9')) ? ch : '_';
  return value;
}

static bool pacSessionSummaryPrefix(const PacIpv6Session &session,
                                    string &prefix, bool &enabled)
{
  vector<FieldValueTuple> fields;
  string lengthText;
  prefix.clear();
  enabled = false;
  if (!Fp->m_PacIpv6ProfileTbl.get(session.profile, fields))
    return false;
  for (const auto &entry : fields)
    if (fvField(entry) == "route_summary_prefix_length")
      lengthText = fvValue(entry);
  if (lengthText.empty() || lengthText == "0")
    return true;

  uint64_t prefixLength;
  if (!pacParseUnsigned(lengthText, prefixLength) || prefixLength < 1 || prefixLength > 128)
    return false;
  struct in6_addr addressBytes;
  if (inet_pton(AF_INET6, session.address.c_str(), &addressBytes) != 1)
    return false;
  for (size_t bit = static_cast<size_t>(prefixLength); bit < 128; ++bit)
    addressBytes.s6_addr[bit / 8] &= static_cast<uint8_t>(~(1U << (7U - (bit % 8U))));
  char addressText[PAC_IPV6_ADDRESS_TEXT_LEN];
  if (inet_ntop(AF_INET6, &addressBytes, addressText, sizeof(addressText)) == NULL)
    return false;
  prefix = string(addressText) + "/" + to_string(prefixLength);
  enabled = true;
  return true;
}

static bool pacBGPRouteReconcile(const vector<PacIpv6Session> &sessions)
{
  map<string, uint32_t> desiredRoutes;
  for (const auto &session : sessions)
  {
    string prefix;
    bool enabled;
    if (!pacSessionSummaryPrefix(session, prefix, enabled))
      return false;
    if (enabled)
      ++desiredRoutes[prefix];
  }

  vector<string> managedRoutes;
  Fp->m_PacIpv6RouteSummaryOperTbl.getKeys(managedRoutes);
  set<string> managed(managedRoutes.begin(), managedRoutes.end());

  // Do not overwrite a route owned by static-route configuration or another
  // application. PAC may reuse a route only when its own operational record
  // proves that PAC created it previously.
  for (const auto &route : desiredRoutes)
  {
    if (managed.count(route.first) != 0)
      continue;
    vector<FieldValueTuple> existingFields;
    if (Fp->m_PacRuntimeStaticRouteTable.get(route.first, existingFields) ||
        Fp->m_ConfigStaticRouteTbl.get("default|" + route.first, existingFields) ||
        Fp->m_ConfigStaticRouteTbl.get(route.first, existingFields))
      return false;
  }

  for (const auto &route : desiredRoutes)
  {
    vector<FieldValueTuple> routeFields = {
      {"blackhole", "true"}, {"advertise", "true"}
    };
    Fp->m_PacRuntimeStaticRouteTable.set(route.first, routeFields);
    vector<FieldValueTuple> stateFields = {
      {"prefix", route.first}, {"session_count", to_string(route.second)}
    };
    Fp->m_PacIpv6RouteSummaryOperTbl.set(route.first, stateFields);
  }

  for (const auto &prefix : managed)
  {
    if (desiredRoutes.count(prefix) != 0)
      continue;
    Fp->m_PacRuntimeStaticRouteTable.del(prefix);
    Fp->m_PacIpv6RouteSummaryOperTbl.del(prefix);
  }
  return true;
}

static bool pacAclReconcile(const vector<PacIpv6Session> &sessions)
{
  static const string aclType = "PAC_IPV6_SESSION_TYPE";
  const vector<FieldValueTuple> typeFields = {
    {"MATCHES", "SRC_IPV6,DST_IPV6,IP_PROTOCOL,ICMPV6_TYPE"},
    {"ACTIONS", "PACKET_ACTION"},
    {"BPOINT_TYPES", "PORT"}
  };
  static bool aclTypePublished = false;
  if (!aclTypePublished)
  {
    Fp->m_PacRuntimeAclTableType.set(aclType, typeFields);
    aclTypePublished = true;
  }

  map<string, map<string, vector<FieldValueTuple>>> desiredRules;
  set<string> interfaces;
  for (const auto &session : sessions) interfaces.insert(session.interfaceName);

  for (const auto &interfaceName : interfaces)
  {
    for (const auto &stage : {string("INGRESS"), string("EGRESS")})
    {
      const string tableName = pacAclTableName(interfaceName, stage);
      // Cumulus permits Neighbor Discovery independently of the tenant data
      // policy so hosts can resolve neighbors and routers on the link.
      for (const auto &type : {string("133"), string("134"), string("135"), string("136")})
        desiredRules[tableName]["ALLOW_ND_" + type] = {
          {"PRIORITY", "300"}, {"PACKET_ACTION", "FORWARD"},
          {"IP_PROTOCOL", "58"}, {"ICMPV6_TYPE", type}
        };

      // This is the terminal IPv6 policy: only the explicit tenant-group
      // permit above it can pass. Non-IPv6 traffic is unaffected.
      desiredRules[tableName]["DROP_OTHER_IPV6"] = {
        {"PRIORITY", "1"}, {"PACKET_ACTION", "DROP"}, {"SRC_IPV6", "::/0"}
      };
    }
  }

  for (const auto &source : sessions)
  {
    const string groupToken = pacSafeRulePart(source.profile) + "_" +
                              pacSafeRulePart(source.isolationId);
    for (const auto &stage : {string("INGRESS"), string("EGRESS")})
    {
      const string tableName = pacAclTableName(source.interfaceName, stage);
      desiredRules[tableName]["ALLOW_TENANT_" + groupToken] = {
        {"PRIORITY", "200"}, {"PACKET_ACTION", "FORWARD"},
        {"SRC_IPV6", source.isolationId},
        {"SRC_IPV6_MASK", source.isolationMask},
        {"DST_IPV6", source.isolationId},
        {"DST_IPV6_MASK", source.isolationMask}
      };
    }
  }

  // Create or update all required tables and wait until the ACL orchestrator
  // has bound each table before sending its rules.
  for (const auto &interfaceName : interfaces)
  {
    for (const auto &stage : {string("INGRESS"), string("EGRESS")})
    {
      const string tableName = pacAclTableName(interfaceName, stage);
      vector<FieldValueTuple> fields = {
        {"policy_desc", "PAC dynamic IPv6 tenant isolation"},
        {"type", aclType}, {"stage", stage}, {"ports", interfaceName}
      };
      Fp->m_PacRuntimeAclTable.set(tableName, fields);
      if (!pacAclWait(Fp->m_AclTableState, tableName)) return false;
    }
  }

  // Install and confirm new policy before removing entries left by old sessions.
  for (const auto &table : desiredRules)
  {
    for (const auto &rule : table.second)
    {
      Fp->m_PacRuntimeAclRuleTable.set(table.first + ":" + rule.first, rule.second);
      if (!pacAclWait(Fp->m_AclRuleState, table.first + "|" + rule.first))
        return false;
    }
  }

  vector<string> configuredRules;
  Fp->m_PacRuntimeAclRuleTable.getKeys(configuredRules);
  for (const auto &key : configuredRules)
  {
    if (key.compare(0, 5, "PAC6_") != 0) continue;
    const size_t separator = key.find(':');
    if (separator == string::npos) continue;
    const string tableName = key.substr(0, separator);
    const string ruleName = key.substr(separator + 1);
    auto tableIt = desiredRules.find(tableName);
    if (tableIt == desiredRules.end() || tableIt->second.count(ruleName) == 0)
      Fp->m_PacRuntimeAclRuleTable.del(key);
  }

  vector<string> configuredTables;
  Fp->m_PacRuntimeAclTable.getKeys(configuredTables);
  for (const auto &tableName : configuredTables)
  {
    if (tableName.compare(0, 5, "PAC6_") != 0) continue;
    bool tableNeeded = false;
    for (const auto &interfaceName : interfaces)
      tableNeeded |= tableName == pacAclTableName(interfaceName, "INGRESS") ||
                     tableName == pacAclTableName(interfaceName, "EGRESS");
    if (!tableNeeded)
      Fp->m_PacRuntimeAclTable.del(tableName);
  }
  return true;
}

string fetch_interface_name(int intIfNum)
{
  string name("");
   char8 ifName[ NIM_IF_ALIAS_SIZE + 1];

  if (nimGetIntfName(intIfNum,  ALIASNAME, ( uchar8*)ifName) !=  SUCCESS)
  {
	   return "FAILURE";
  }
  
  name = ifName;
  return name;
}

int PacAuthClientOperTblSet(uint32 intIfNum,  enetMacAddr_t macAddr,
                            pac_authenticated_clients_oper_table_t *client_info)
{
  vector<FieldValueTuple> fvs;
  char c[18];
  unsigned int i;
  string serverState("");
  string serverClass("");
   enetMacAddr_t zeroMac;

  SWSS_LOG_NOTICE("----- PacAuthClientOperTbl func called from AuthMgr -----");

  memset (&zeroMac, 0, sizeof ( enetMacAddr_t));
  if (0 == memcmp (zeroMac.addr, macAddr.addr,  ENET_MAC_ADDR_LEN))
  {
    return SUCCESS;
  }

  if ( AUTHMGR_PORT_STATUS_AUTHORIZED != client_info->auth_status)
  {
    return SUCCESS;
  }

  string userName(client_info->userName, 
                  client_info->userName + 
                  sizeof(client_info->userName)/sizeof(client_info->userName[0]));  

  memset(c, 0, sizeof(c));

  sprintf(c, "%02X:%02X:%02X:%02X:%02X:%02X",
          macAddr.addr[0], macAddr.addr[1], macAddr.addr[2],
          macAddr.addr[3], macAddr.addr[4], macAddr.addr[5]);

  string macAddress(c);

  string interfaceName = fetch_interface_name(intIfNum);

  string key = interfaceName + "|";

  key += macAddress;

  string oldAddress;
  pacStateField(Fp->m_PacAuthClientOperTbl, key, "ipv6_address", oldAddress);
  string profileName;
  string ipv6Address;
  string isolationId;
  string isolationMask;
  vector<FieldValueTuple> associationFields;
  bool profileConfigured = Fp->m_PacPortIpv6ProfileTbl.get(interfaceName, associationFields);
  bool addressBuilt = pacIpv6AddressBuild(interfaceName, client_info, profileName,
                                          ipv6Address, isolationId, isolationMask);
  if (profileConfigured && !addressBuilt)
    return FAILURE;
  if (!ipv6Address.empty())
  {
    PacIpv6Session pending;
    pending.key = key;
    pending.interfaceName = interfaceName;
    pending.mac = macAddress;
    pending.address = ipv6Address;
    pending.profile = profileName;
    pending.isolationId = isolationId;
    pending.isolationMask = isolationMask;
    vector<PacIpv6Session> sessions = pacActiveIpv6Sessions(key, &pending);
    for (const auto &session : sessions)
    {
      if (session.key != key && session.address == ipv6Address)
        return FAILURE;
    }
    if (!pacAclReconcile(sessions) ||
        !pacIpv6AddressChange(interfaceName, ipv6Address, true))
    {
      pacAclReconcile(pacActiveIpv6Sessions("", NULL));
      return FAILURE;
    }
    if (!pacBGPRouteReconcile(sessions))
    {
      if (oldAddress != ipv6Address)
        pacIpv6AddressChange(interfaceName, ipv6Address, false);
      pacAclReconcile(pacActiveIpv6Sessions("", NULL));
      pacBGPRouteReconcile(pacActiveIpv6Sessions("", NULL));
      return FAILURE;
    }
  }
  else if (!oldAddress.empty())
  {
    vector<PacIpv6Session> sessions = pacActiveIpv6Sessions(key, NULL);
    pacAclReconcile(sessions);
    pacBGPRouteReconcile(sessions);
    pacIpv6AddressChange(interfaceName, oldAddress, false);
  }
  fvs.emplace_back("ipv6_profile", profileName);
  fvs.emplace_back("ipv6_address", ipv6Address);
  fvs.emplace_back("isolation_id", isolationId);
  fvs.emplace_back("isolation_mask", isolationMask);

  fvs.emplace_back("current_id", to_string(client_info->currentIdL));
  fvs.emplace_back("auth_status", authMgrPortStatus[client_info->auth_status]);
  fvs.emplace_back("authenticated_method", authMgrMethod[client_info->authenticatedMethod]);

  for (i = 0; i < client_info->serverStateLen; i++) 
  {
    memset(c, 0, sizeof(c));
    sprintf(c, "%02X", client_info->serverState[i]);
    serverState += c;
  }

  fvs.emplace_back("server_state", serverState);
  fvs.emplace_back("server_state_len", to_string(client_info->serverStateLen));

  for (i = 0; i < client_info->serverClassLen; i++) 
  {
    memset(c, 0, sizeof(c));
    sprintf(c, "%02X", client_info->serverClass[i]);
    serverState += c;
  }

  fvs.emplace_back("server_class", serverClass);
  fvs.emplace_back("server_class_len", to_string(client_info->serverClassLen));

  fvs.emplace_back("session_timeout_RADIUS", to_string(client_info->sessionTimeoutRcvdFromRadius));
  fvs.emplace_back("session_timeout_oper", to_string(client_info->sessionTimeoutOper));
  fvs.emplace_back("user_name", userName);
  fvs.emplace_back("user_name_len", to_string(client_info->userNameLen));
  fvs.emplace_back("termination_action", to_string(client_info->terminationAction));
  fvs.emplace_back("vlan_id", to_string(client_info->vlanId));
  fvs.emplace_back("tenant_id", client_info->tenantIdPresent ?
                    to_string(client_info->tenantId) : "");
  fvs.emplace_back("vlan_type", vlanType[client_info->vlanType]);
  fvs.emplace_back("backend_auth_method", userMgrAuthMethod[client_info->backend_auth_method]);
  fvs.emplace_back("session_time", to_string(client_info->sessionTime));
  fvs.emplace_back("termination_action_time_left", to_string(client_info->lastAuthTime));

  Fp->m_PacAuthClientOperTbl.set(key, fvs);
  if (!oldAddress.empty() && oldAddress != ipv6Address)
    pacIpv6AddressChange(interfaceName, oldAddress, false);
  return SUCCESS;
 }

void PacAuthClientOperTblDel(uint32 intIfNum,  enetMacAddr_t macAddr)
{
  string interfaceName = fetch_interface_name(intIfNum);

  char c[18];

  sprintf(c, "%02X:%02X:%02X:%02X:%02X:%02X",
          macAddr.addr[0], macAddr.addr[1], macAddr.addr[2],
          macAddr.addr[3], macAddr.addr[4], macAddr.addr[5]);

  string macAddress(c);

  string key = interfaceName + "|";
  key += macAddress;

  string address;
  pacStateField(Fp->m_PacAuthClientOperTbl, key, "ipv6_address", address);
  vector<PacIpv6Session> sessions = pacActiveIpv6Sessions(key, NULL);
  pacAclReconcile(sessions);
  pacBGPRouteReconcile(sessions);
  if (!address.empty())
    pacIpv6AddressChange(interfaceName, address, false);
  Fp->m_PacAuthClientOperTbl.del(key);

}

void PacAuthClientOperTblCleanup(void)
{
   vector<string> keys;
   Fp->m_PacAuthClientOperTbl.getKeys(keys);
   for (const auto &key : keys)
   {
      size_t separator = key.find('|');
      string address;
      if (separator != string::npos &&
          pacStateField(Fp->m_PacAuthClientOperTbl, key, "ipv6_address", address) &&
          !address.empty())
        pacIpv6AddressChange(key.substr(0, separator), address, false);
      Fp->m_PacAuthClientOperTbl.del(key);
   }
   pacAclReconcile(vector<PacIpv6Session>());
   pacBGPRouteReconcile(vector<PacIpv6Session>());
}

void PacGlobalOperTblSet(pac_global_oper_table_t *info)
{
  vector<FieldValueTuple> fvs;
  
  SWSS_LOG_NOTICE("----- PacOperTbl API called from AuthMgr -----");

  fvs.emplace_back("num_clients_authenticated", to_string(info->authCount));
  fvs.emplace_back("num_clients_authenticated_monitor", to_string(info->authCountMonMode));

  Fp->m_PacGlobalOperTbl.set("GLOBAL", fvs);
}

void PacGlobalOperTblCleanup(void)
{
   vector<string> keys;
   Fp->m_PacGlobalOperTbl.getKeys(keys);
   for (const auto key : keys)
   {
      Fp->m_PacGlobalOperTbl.del(key);
   }
}

void PacPortOperTblSet(uint32 intIfNum,  AUTHMGR_METHOD_t *enabledMethods, 
                        AUTHMGR_METHOD_t *enabledPriority)
{
  vector<FieldValueTuple> fvs;
  uint32 idx;
  string methods("");
  string priorities("");
  
  SWSS_LOG_NOTICE("----- PacPortOperTbl API called from AuthMgr -----");

  string key = fetch_interface_name(intIfNum);

  for (idx = 0; idx < 2; idx++)
  {
    if (idx != 0)
    {
      methods += ",";
    }
     
    if (!enabledMethods[idx])
    {
      methods += "undefined"; 
    }
    else
    {
      if ( AUTHMGR_METHOD_8021X == enabledMethods[idx])
      {
        methods += "dot1x"; 
      }
      else if ( AUTHMGR_METHOD_MAB == enabledMethods[idx])
      {
        methods += "mab"; 
      }
    }
  }

  for (idx = 0; idx < 2; idx++)
  {
    if (idx != 0)
    {
      priorities += ",";
    }
    if (!enabledPriority[idx])
    {
      priorities += "undefined"; 
    }
    else
    {
      if ( AUTHMGR_METHOD_8021X == enabledPriority[idx])
      {
        priorities += "dot1x"; 
      }
      else if ( AUTHMGR_METHOD_MAB == enabledPriority[idx])
      {
        priorities += "mab"; 
      }
    }
  }

  fvs.emplace_back("enabled_method_list@", methods);
  fvs.emplace_back("enabled_priority_list@", priorities);
  
  Fp->m_PacPortOperTbl.set(key, fvs);
}

void PacPortOperTblCleanup(void)
{
   vector<string> keys;
   Fp->m_PacPortOperTbl.getKeys(keys);
   for (const auto key : keys)
   {
      Fp->m_PacPortOperTbl.del(key);
   }
}


void PacOperTblCleanup(void)
{
   PacAuthClientOperTblCleanup();
   PacGlobalOperTblCleanup();
}


