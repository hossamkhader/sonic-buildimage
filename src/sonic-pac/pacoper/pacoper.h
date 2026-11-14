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
#ifndef PACOPER_H
#define PACOPER_H

#include <vector>
#include <swss/dbconnector.h>
#include <swss/schema.h>
#include <swss/table.h>
#include <swss/macaddress.h>
#include <swss/producerstatetable.h>
#include <swss/table.h>
#include <swss/select.h>
#include <swss/timestamp.h>
#include <swss/redisapi.h>
#include <swss/tokenize.h>

using namespace swss;
using namespace std;

#define AUTHMGR_MAX_HISTENT_PER_INTERFACE   48

class FpDbAdapter {
public:
    FpDbAdapter(DBConnector *stateDb, DBConnector *configDb, DBConnector *appDb);
    Table m_PacGlobalOperTbl;
    Table m_PacPortOperTbl;
    Table m_PacAuthClientOperTbl;
    Table m_PacIpv6ProfileTbl;
    Table m_PacIpv6ProfilePropertyTbl;
    Table m_PacPortIpv6ProfileTbl;
    Table m_ConfigStaticRouteTbl;
    ProducerStateTable m_PacRuntimeAclTableType;
    ProducerStateTable m_PacRuntimeAclTable;
    ProducerStateTable m_PacRuntimeAclRuleTable;
    // bgpcfgd reads APPL_DB STATIC_ROUTE with a SubscriberStateTable (keyspace
    // events on STATIC_ROUTE:<prefix>), like the entries staticroutebfd
    // writes, so this must be a plain Table rather than a ProducerStateTable.
    Table m_PacRuntimeStaticRouteTable;
    Table m_PacIpv6RouteSummaryOperTbl;
    Table m_AclTableState;
    Table m_AclRuleState;
    // Read-only views of the APPL_DB tables written above (ProducerStateTable
    // cannot read).
    Table m_PacRuntimeAclTableReader;
    Table m_PacRuntimeAclRuleReader;
    Table m_PacRuntimeStaticRouteReader;
    // Routed-port switching: vlanmgrd takes a port out of its VLANs while
    // OPER_PORT "pac_routed" is set; orchagent then accepts the router
    // interface and the session addresses written to APPL_DB INTF_TABLE.
    Table m_OperPortTbl;
    Table m_VlanMemberState;
    ProducerStateTable m_PacRuntimeIntfTable;
    Table m_PacIpv6RoutedPortOperTbl;

private:
};

string fetch_interface_name(int);

#endif /* PACOPER_H */
