import json
import base64
from ldap3 import ALL_ATTRIBUTES, LEVEL


class IPAobjectCollector(object):
    def __init__(self, client, base_dn, timestamp, logger, ipa_type, use_ladp=False, dn='', filter='(objectclass=*)'):
        self.ipa_objects = {"graph": {"nodes": [], "edges": []}, "metadata": {"source_kind": "IPABase"}}
        self.logger = logger
        self.ipa_type = ipa_type
        self.dn = dn
        self.client = client
        self.filter = filter
        self.base_dn = base_dn
        if use_ladp:
            self.collect_from_ldap()
        else:
            self.collect_from_api()
        self.create_json(timestamp)


    def collect_from_api(self):
        ipa_find = getattr(self.client, f'{self.ipa_type}_find')
        ipa_objects = ipa_find(o_sizelimit=0)
        if ipa_objects['result']:
            for ipa_object in ipa_objects['result']:
                node, edges = self.api_parse_objects(ipa_object)
                self.ipa_objects["graph"]["nodes"].append(node)
                self.ipa_objects["graph"]["edges"].extend(edges)
                count = len(self.ipa_objects['graph'])
                #self.ipa_objects['meta']['count'] = count
            self.logger.info(f'collected {count} {self.ipa_type}...')
        else:
            self.logger.info(f'collected 0 {self.ipa_type}...')


    def api_parse_objects(self, ipa_object):
        ipa_type_mapper = {'trust': 'IPATrust','user': 'IPAUser', 'group': 'IPAUserGroup', 'privilege': 'IPAPrivilege', 'permission': 'IPAPermission', 'sudorule': 'IPASudoRule', 'role': 'IPARole', 'hostgroup': 'IPAHostGroup', 'netgroup': 'IPANetGroup', 'hbacrule': 'IPAHBACRule', 'host': 'IPAHost', 'sysaccounts':'IPASysAccount', 'service': 'IPAService', 'sudocmd': 'IPASudo', 'sudocmdgroup': 'IPASudoGroup', 'hbacservices': 'IPAHBACService', 'hbacservicegroups': 'IPAHBACServiceGroup', 'hbacsvc': 'IPAHBACService', 'hbacsvcgroup': 'IPAHBACServiceGroup'}
        edges = []
        node = {"id": "","name": "", "kinds": [], "properties": {}}
        node['kinds'].append(ipa_type_mapper[self.ipa_type])
        node['kinds'].append("IPABase")
        if 'uid' in ipa_object.keys():
            name = ipa_object['uid'][0]
        elif 'cn' in ipa_object.keys():
            name = ipa_object['cn'][0]
        else:
            name = ipa_object['ipauniqueid'][0]

        id_name = ipa_type_mapper[self.ipa_type] + "_" + name

        if 'ipantsecurityidentifier' in ipa_object.keys():
            id = ipa_object['ipantsecurityidentifier'][0]
            # test ipantsecurityidentifier to ad sid matching edge
            edges.append({"kind": "SIDmatches", "start": {"value": id, "kind": "Base"}, "end": {"value": id_name},"properties": None})
            edges.append({"kind": "SIDmatches", "start": {"value": id_name}, "end": {"value": id, "kind": "Base"},"properties": None})

        #node['id'] = id
        node['id'] = id_name
        node['name'] = name
        node['properties']['name'] = name
        node['properties']['object_id'] = name
        node['properties']['highvalue'] = False
        for attribute in ipa_object:
            if attribute.startswith('member'):
                for member in ipa_object[attribute]:
                    if attribute.startswith('memberof_'):
                        edges.append(self.edge_builder(attribute, attribute.split('_')[-1], member, id_name))
                    elif attribute == 'memberof':
                        edges.append(self.edge_builder('memberof', 'group', member, id_name))
                    elif attribute.startswith('memberofindirect_'):
                        edges.append(self.edge_builder(attribute, attribute.split('_')[-1], member, id_name))
                    else:
                        #edges.append(self.edge_builder('member', attribute.split('_')[-1], member, id_name))
                        pass
            elif attribute.startswith('manag'):
                for member in ipa_object[attribute]:
                    if attribute.startswith('managedby_'):
                        edges.append(self.edge_builder('managedby', attribute.split('_')[-1], member, id_name))
                    elif attribute.startswith('managing_'):
                        edges.append(self.edge_builder('managing', attribute.split('_')[-1], member, id_name))
            if not isinstance(ipa_object[attribute], bool):
                if isinstance(ipa_object[attribute][0], dict) and '__base64__' in ipa_object[attribute][0].keys():
                    if 'cert' in attribute or '':
                        node['properties'][attribute] = ipa_object[attribute][0]['__base64__']
                    else:
                        node['properties'][attribute] = base64.b64decode(ipa_object[attribute][0]['__base64__']).decode('utf-8', errors='ignore')
                elif isinstance(ipa_object[attribute][0], dict) and '__datetime__' in ipa_object[attribute][0].keys():
                    node['properties'][attribute] = ipa_object[attribute][0]['__datetime__']
                elif len(ipa_object[attribute]) == 1:
                    node['properties'][attribute] = ipa_object[attribute][0]
                else:
                    node['properties'][attribute] = ipa_object[attribute]
        return node, edges



    def collect_from_ldap(self):
        self.client.search(f'{self.dn}',self.filter, LEVEL, attributes=ALL_ATTRIBUTES)
        if self.client.entries:
            for entry in self.client.entries:
                entry = json.loads(entry.entry_to_json())
                entry['attributes']['dn'] = entry['dn']
                properties, edges = self.ldap_parse_entries(entry)
                self.ipa_objects['data'].append({'Properties': properties, 'Edges': edges})
                count = len(self.ipa_objects['data'])
                self.ipa_objects['meta']['count'] = count
            self.logger.info(f'collected {count} {self.ipa_type}...')
        else:
            self.logger.info(f'collected 0 {self.ipa_type}...')


    def ldap_parse_entries(self, entry):
        member_mapper = {'cn=permissions,cn=pbac': 'permission', 'cn=groups,cn=accounts':'group', 'cn=hostgroups,cn=accounts':'hostgroup', 'cn=ng,cn=alt':'netgroup', 'cn=roles,cn=accounts': 'role', 'cn=sudorules,cn=sudo': 'sudorule', 'cn=sudocmds,cn=sudo': 'sudocmd', 'cn=sudocmdgroups,cn=sudo': 'sudocmdgroup', 'cn=hbac': 'hbacrule', 'cn=privileges,cn=pbac': 'privilege', 'cn=computers,cn=accounts': 'host', 'cn=users,cn=accounts': 'user', 'cn=services,cn=accounts': 'service', 'cn=trusts': 'trust', 'cn=sysaccounts,cn=etc': 'sysaccounts', 'cn=hbacservices,cn=hbac': 'hbacservices', 'cn=hbacservicegroups,cn=hbac': 'hbacservicegroups'}
        edges = []
        properties = {}
        if 'uid' in entry['attributes'].keys():
            name = entry['attributes']['uid'][0]
        elif 'cn' in entry['attributes'].keys():
            name = entry['attributes']['cn'][0]
        else:
            name = entry['attributes']['ipaUniqueID'][0]
        properties['name'] = name
        properties['object_id'] = name
        properties['highvalue'] = False
        for attribute in entry['attributes']:
            if 'manag' in attribute.lower():
                for member in entry['attributes'][attribute]:
                    member = member[:-len(self.base_dn)-1]
                    member, path = member.split(',', 1)
                    mapped_type = member_mapper[path]
                    if attribute == 'mepManagedEntry':
                        edges.append(self.edge_builder('managing', mapped_type, member.split('=', 1)[-1], name))
                    elif attribute == 'managedBy':
                        edges.append(self.edge_builder('managedby', mapped_type, member.split('=', 1)[-1], name))
                    elif attribute == 'mepManagedBy':
                        edges.append(self.edge_builder('managedby', mapped_type, member.split('=', 1)[-1], name))
            elif attribute.startswith('member'):
                for member in entry['attributes'][attribute]:
                    member = member[:-len(self.base_dn)-1]
                    member, path = member.split(',', 1)
                    mapped_type = member_mapper[path]
                    edges.append(self.edge_builder(attribute.lower(), mapped_type, member.split('=', 1)[-1], name))
            else:
                if len(entry['attributes'][attribute]) == 1:
                    properties[attribute.lower()] = entry['attributes'][attribute][0]
                else:
                    properties[attribute.lower()] = entry['attributes'][attribute]
                if isinstance(entry['attributes'][attribute], dict) and 'encoding' in entry['attributes'][attribute].keys():
                    properties[attribute.lower()] = entry['attributes']['encoded']
        return properties, edges


    def edge_builder(self, relation_type, target_type, target, source_name):
        ipa_type_mapper = {'user': 'IPAUser', 'group': 'IPAUserGroup', 'privilege': 'IPAPrivilege', 'permission': 'IPAPermission', 'sudorule': 'IPASudoRule', 'role': 'IPARole', 'hostgroup': 'IPAHostGroup', 'netgroup': 'IPANetGroup', 'hbacrule': 'IPAHBACRule', 'host': 'IPAHost', 'sysaccounts':'IPASysAccount', 'service': 'IPAService', 'sudocmd': 'IPASudo', 'sudocmdgroup': 'IPASudoGroup', 'hbacservices': 'IPAHBACService', 'hbacservicegroups': 'IPAHBACServiceGroup', 'hbacsvc': 'IPAHBACService', 'hbacsvcgroup': 'IPAHBACServiceGroup'}
        acl_type_mapper = {'sudorule': 'IPASudoRuleTo', 'hbacrule': 'IPAHBACRuleTo'}

        target_name = ipa_type_mapper[target_type] + "_" + target

        if self.ipa_type in acl_type_mapper:
            edge = {"kind": acl_type_mapper[self.ipa_type], "start": {"match_by": "id", "value": target_name, "kind": ipa_type_mapper[target_type]}, "end": {"match_by": "id", "value": source_name, "kind": ipa_type_mapper[self.ipa_type]}}
            if 'deny' in relation_type or 'allow' in relation_type:
                edge['properties']['allow'] = 'allow' in relation_type
        elif relation_type.startswith('memberof_'):
            edge = {"kind": "IPAMemberOf_" + relation_type.split('_')[-1].capitalize(), "start": {"match_by": "id", "value": source_name, "kind": ipa_type_mapper[self.ipa_type]}, "end": {"match_by": "id", "value": target_name, "kind": ipa_type_mapper[target_type]},"properties": None}
        elif target_type in acl_type_mapper:
            edge = {"kind": acl_type_mapper[target_type], "start": {"match_by": "id", "value": source_name, "kind": ipa_type_mapper[self.ipa_type]}, "end": {"match_by": "id", "value": target_name, "kind": ipa_type_mapper[target_type]}}
        elif relation_type == 'managedby':
            edge = {"kind":"IPAManagedBy", "start": {"match_by": "id", "value": source_name, "kind": ipa_type_mapper[self.ipa_type]}, "end": {"match_by": "id", "value": target_name, "kind": ipa_type_mapper[target_type]}}
        elif relation_type == 'managing':
            edge = {"kind":"IPAManaging", "start": {"match_by": "id", "value": target_name, "kind": ipa_type_mapper[target_type]}, "end": {"match_by": "id", "value": source_name, "kind": ipa_type_mapper[self.ipa_type]}}
        else:
            if relation_type == 'memberof':
                edge = {"kind": "IPAMemberOf", "start": {"match_by": "id", "value": source_name, "kind": ipa_type_mapper[self.ipa_type]}, "end": {"match_by": "id", "value": target_name, "kind": ipa_type_mapper[target_type]},"properties": None}
            else:
                edge = {"kind": "IPAMemberOf_" + relation_type.split('_')[-1].capitalize(), "start": {"match_by": "id", "value": source_name, "kind": ipa_type_mapper[self.ipa_type]}, "end": {"match_by": "id", "value": target_name, "kind": ipa_type_mapper[target_type]},"properties": None}
        return edge


    def create_json(self, timestamp):
        with open(f'{timestamp}_ipa_{self.ipa_type}s.json', 'w') as f:
            f.write(json.dumps(self.ipa_objects))
        self.logger.info(f'\tsaved {self.ipa_type}s to file {timestamp}_ipa_{self.ipa_type}s.json')


    def parse_user_rights(self, uid):
        rights = self.client.user_show(uid)['result']['attributelevelrights']
