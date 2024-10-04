import logging
import time
import psycopg2
from psycopg2 import sql
import datetime

from ipaddress import IPv4Network, IPv6Network, AddressValueError
# from data.checkAccessor import checkCyhyRunning, checkVMrunning
# from data.config import db_config, db_password_key
from data.cyhy_db_query import mongo_connect, mdl_staging_connect, show_psycopg2_exception

LOGGER = logging.getLogger(__name__)

def save_sector(conn, sector_obj):
    try:
        cur = conn.cursor()
        insert_query = sql.SQL("""
            INSERT INTO sector (name, acronym, retired)
            VALUES (%s, %s, %s)
            ON CONFLICT (acronym) DO UPDATE
            SET name = EXCLUDED.name,
                retired = EXCLUDED.retired
            RETURNING id
        """)
        cur.execute(
            insert_query,
            (
                sector_obj.get('name', None),
                sector_obj.get('acronym',None),
                sector_obj.get('retired', None)
            ),
        )

        new_sector_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        return new_sector_id

    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        LOGGER.error(sector_obj)
        return None

def saveOrgToMdl(conn, orgObj, networkList, location):
    try:
        cur = conn.cursor()

        insert_query = sql.SQL("""
            INSERT INTO organization (name, acronym, retired, type, stakeholder, "enrolledInVsTimestamp", "periodStartVsTimestamp", "reportTypes", "scanTypes")
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (acronym) DO UPDATE
            SET name = EXCLUDED.name,
                retired = EXCLUDED.retired,
                type = EXCLUDED.type,
                stakeholder = EXCLUDED.stakeholder,
                "enrolledInVsTimestamp" = EXCLUDED."enrolledInVsTimestamp",
                "periodStartVsTimestamp" = EXCLUDED."periodStartVsTimestamp",
                "reportTypes" = EXCLUDED."reportTypes",
                "scanTypes" = EXCLUDED."scanTypes"
            RETURNING id
        """)

        # Extract values from orgObj
        values = (
            orgObj.get('name'),
            orgObj.get('acronym'),
            orgObj.get('retired'),
            orgObj.get('type'),
            orgObj.get('stakeholder'),
            orgObj.get('enrolledInVsTimestamp'),
            orgObj.get('periodStartVsTimestamp'),
            orgObj.get('reportTypes'),
            orgObj.get('scanTypes')
        )

        cur.execute(insert_query, values)
        org_id = cur.fetchone()[0]

        conn.commit()
        cur.close()

    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        LOGGER.error(f"{orgObj.get('name', None)} failed to save")
        org_id = None
        
    if org_id:
        for network in networkList:
            try:
                cur = conn.cursor()
                insert_query = sql.SQL("""
                    INSERT INTO cidr (network, "startIp", "endIp")
                    VALUES (%s, %s, %s)
                    ON CONFLICT (network) DO UPDATE
                    SET "startIp" = EXCLUDED."startIp",
                        "endIp" = EXCLUDED."endIp"
                    RETURNING id
                """)
                cur.execute(
                    insert_query,
                    (
                        network.get('network', None),
                        network.get('startIp',None),
                        network.get('endIp', None)
                    ),
                )

                network_id = cur.fetchone()[0]
                conn.commit()
                cur.close()

            except (Exception, psycopg2.DatabaseError) as err:
                show_psycopg2_exception(err)
                LOGGER.error(network)
                network_id = None
            
            if network_id:
                # network_ids.append(network_id)
                try:
                    cur = conn.cursor()
                    insert_query = sql.SQL("""
                        INSERT INTO cidr_organizations_organization("cidrId", "organizationId")
                        VALUES (%s, %s)
                        ON CONFLICT ("cidrId", "organizationId")
                        DO NOTHING
                    """)

                    cur.execute(
                        insert_query,
                        (
                            network_id,
                            org_id
                        ),
                    )
                    conn.commit()
                    cur.close()
                except (Exception, psycopg2.DatabaseError) as err:
                    show_psycopg2_exception(err)
                    LOGGER.error(network)
    
        if location:
            try:
                cur = conn.cursor()
                insert_query = sql.SQL("""
                    INSERT INTO location (name, "countryAbrv", country, county, "countyFips", "gnisId", "stateAbrv", "stateFips", state)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT ("gnisId") DO UPDATE
                    SET name = EXCLUDED.name,
                        "countryAbrv" = EXCLUDED."countryAbrv",
                        country = EXCLUDED.country,
                        county = EXCLUDED.county,
                        "countyFips" = EXCLUDED."countyFips",
                        "stateAbrv" = EXCLUDED."stateAbrv",
                        "stateFips" = EXCLUDED."stateFips",
                        state = EXCLUDED.state
                    RETURNING id
                """)

                cur.execute(
                    insert_query,
                    (
                        location.get('name', None),
                        location.get('countryAbrv',None),
                        location.get('country', None),
                        location.get('county', None),
                        location.get('countyFips', None),
                        location.get('gnisId', None),
                        location.get('stateAbrv', None),
                        location.get('stateFips', None),
                        location.get('state', None),
                    ),
                )

                location_id = cur.fetchone()[0]
                conn.commit()
                cur.close()

            except (Exception, psycopg2.DatabaseError) as err:
                show_psycopg2_exception(err)
                LOGGER.error(network)
                location_id = None

            if location_id:
                try:
                    cur = conn.cursor()
                    insert_query = sql.SQL("""
                        INSERT INTO location_organizations_organization("locationId", "organizationId")
                        VALUES (%s, %s)
                        ON CONFLICT ("locationId", "organizationId")
                        DO NOTHING
                    """)

                    cur.execute(
                        insert_query,
                        (
                            location_id,
                            org_id
                        ),
                    )
                    conn.commit()
                    cur.close()
                except (Exception, psycopg2.DatabaseError) as err:
                    show_psycopg2_exception(err)
                    LOGGER.error(network)
    return org_id

def linkSectorOrg(conn, sector_org):
    try:

        cur = conn.cursor()
        insert_query = sql.SQL("""
            INSERT INTO sector_organizations_organization("sectorId", "organizationId")
            VALUES (%s, %s)
            ON CONFLICT ("sectorId", "organizationId")
            DO NOTHING
        """)
        if sector_org.get('organizationId',None) and sector_org.get('sectorId',None):
            cur.execute(
                insert_query,
                (
                    sector_org.get('sectorId',None),
                    sector_org.get('organizationId',None)
                ),
            )
            conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        LOGGER.error(sector_org)

def linkParentChild(conn, parent, child):
    try:
        cur = conn.cursor()
        insert_query = sql.SQL("""
            UPDATE organization
            SET "parentId" = %s 
            WHERE acronym = %s
        """)
        if parent and child:
            cur.execute(
                insert_query,
                (
                parent,
                child
                ),
            )
            conn.commit()
        cur.close()
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        LOGGER.error(child)

def pull_requests():
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")

    mdl_conn = mdl_staging_connect()

    collection = cyhy_db["requests"]  

    cyhy_request_data = collection.find()
    parent_child_dict = {}
    sector_child_dict={}
    non_sector_list = [
        'CRITICAL_INFRASTRUCTURE',
        'FEDERAL',
        'ROOT',
        'SLTT',
        'CATEGORIES',
        'INTERNATIONAL',
        'THIRD_PARTY'
    ]
    org_id_dict = {}
    for request in cyhy_request_data:
        print(request['_id'])
        # Define as a sector if there is no type
        if request.get('agency',{}).get('type', None) is None:
            if request['_id'] in non_sector_list:
                continue
                
            if 'children' in request and \
            isinstance(request['children'], list) and \
            len(request['children']) > 0:
                sector = {
                    'name':request.get('agency',{}).get('name',None),
                    'acronym':request['_id'],
                    'retired':request.get('retired', None)
                }
                filtered_sector = {key: value for key, value in sector.items() if value is not None}

                sectorId = save_sector(mdl_conn, filtered_sector)
                if sectorId:
                    sector_child_dict[sectorId] = request.get('children',[])
            continue
        # if 'children' in request and \
        # isinstance(request['children'], list) and \
        # len(request['children']) > 0:
        #     parent_child_dict[request['_id']] = request['children']

        networkList = []
        for cidr in request.get('networks',[]):
            try:
                address = IPv6Network(cidr, strict=False) if ':' in cidr else IPv4Network(cidr, strict=False)
                firstIP = str(address.network_address)
                lastIP = str(address.broadcast_address)

                networkList.append({
                    'network':cidr,
                    'startIp':firstIP,
                    'endIp':lastIP
                })

            except AddressValueError as error:
                print(f"Invalid CIDR format: {error}")

        location = None
        loc = request.get('agency',{}).get('location',None)
        if loc:
            location = {
                'name': loc.get('name', None),
                'countryAbrv': loc.get('countryAbrv', None),
                'country': loc.get('country', None),
                'county': loc.get('county', None),
                'countyFips': loc.get('countyFips', None),
                'gnisId': loc.get('gnisId', None),
                'stateAbrv': loc.get('stateAbrv', None),
                'stateFips': loc.get('stateFips', None),
                'state': loc.get('state', None),
            }

        orgObj = {
            'name': request.get('agency',{}).get('name'),
            'acronym': request['_id'],
            'retired': request.get('retired',None),
            'type': request.get('agency',{}).get('type',None),
            'stakeholder': request.get('stakeholder',None),
            'enrolledInVsTimestamp': request.get('enrolled', None),
            'periodStartVsTimestamp': request.get('period_start',None),
            'reportTypes': request.get('report_types', None),
            'scanTypes': request.get('scan_types', None)
        }
        org_id = saveOrgToMdl(mdl_conn, orgObj, networkList, location)

        org_id_dict[request['_id']] = org_id

        if 'children' in request and \
        isinstance(request['children'], list) and \
        len(request['children']) > 0:
            parent_child_dict[org_id] = request['children']


    for key, value in parent_child_dict.items():
        for child in value:
            linkParentChild(mdl_conn, key, child)


    for key, value in sector_child_dict.items():
        for child in value:
            sector_org = {
                'sectorId': key,
                'organizationId': org_id_dict.get(child, None)
            }
            linkSectorOrg(mdl_conn, sector_org)

def query_organizations():
    try:
        # Create a cursor object using the connection
        conn = mdl_staging_connect()
        cur = conn.cursor()

        # Define your select query
        select_query = sql.SQL("""
            SELECT id, acronym
            FROM organization
        """)

        # Execute the select query
        cur.execute(select_query)

        # Fetch all rows from the result set
        rows = cur.fetchall()

        # Construct the dictionary with acronym as key and id as value
        org_dict = {row[1]: row[0] for row in rows}

        # Close the cursor
        cur.close()

        return org_dict
    
    except psycopg2.Error as e:
        print(f"Error querying organizations table: {e}")
        return None
    
def get_value_and_delete(dictionary, key):
    if key in dictionary:
        value = dictionary[key]
        del dictionary[key]
        return value
    else:
        return None
    
def saveIpToMdl(conn, ip_obj):
    try:
        cur = conn.cursor()
        insert_query = sql.SQL("""
            INSERT INTO ip (ip, "organizationId")
            VALUES (%s, %s)
            ON CONFLICT (ip, "organizationId")
            DO UPDATE SET ip = EXCLUDED.ip, "organizationId" = EXCLUDED."organizationId"
            RETURNING id
        """)
        cur.execute(
            insert_query,
            (
                ip_obj.get('ip', None),
                ip_obj.get('organizationId',None)
            ),
        )

        new_ip_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        return new_ip_id

    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        LOGGER.error(ip_obj)
        return None
    
def saveCveToMdl(conn, cve_obj):
    try:
        cur = conn.cursor()
        insert_query = sql.SQL("""
            INSERT INTO cve (name)
            VALUES (%s)
            ON CONFLICT (name)
            DO UPDATE SET name = EXCLUDED.name
            RETURNING id
        """)
        cur.execute(
            insert_query,
            (
                cve_obj.get('name', None),
            ),
        )

        new_cve_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        return new_cve_id

    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        LOGGER.error(cve_obj)
        return None

def saveVulnScan(conn, vuln_scan_obj):
    try:
        cur = conn.cursor()

        # Construct the SQL query using psycopg2.sql.SQL
        insert_query = sql.SQL("""
            INSERT INTO "vuln_scan" (
            "id", "assetInventory", "bid", "certId", "cisaKnownExploited", "ciscoBugId", "ciscoSa", "cpe", "cveId", "cveString",
            "cvss3BaseScore", "cvss3TemporalScore", "cvss3TemporalVector", "cvss3Vector", "cvssBaseScore",
            "cvssScoreRationale", "cvssScoreSource", "cvssTemporalScore", "cvssTemporalVector", "cvssVector",
            "cwe", "description", "exploitAvailable", "exploitabilityEase", "exploitedByMalware", "fName",
            "ipId", "ipString", "latest", "organizationId", "owner", "osvdbId", "patchPublicationTimestamp",
            "pluginFamily", "pluginId", "pluginModificationDate", "pluginName", "pluginOutput", "pluginPublicationDate",
            "pluginType", "port", "portProtocol", "riskFactor", "scriptVersion", "seeAlso", "service", "severity",
            "solution", "source", "synopsis", "thoroughTests", "vulnDetectionTimestamp", "vulnPublicationTimestamp",
            "xref", "otherFindings"
        ) VALUES (
            %(id)s, %(assetInventory)s, %(bid)s, %(certId)s, %(cisaKnownExploited)s, %(ciscoBugId)s,
            %(ciscoSa)s, %(cpe)s, %(cve)s, %(cveString)s, %(cvss3BaseScore)s, %(cvss3TemporalScore)s,
            %(cvss3TemporalVector)s, %(cvss3Vector)s, %(cvssBaseScore)s, %(cvssScoreRationale)s,
            %(cvssScoreSource)s, %(cvssTemporalScore)s, %(cvssTemporalVector)s, %(cvssVector)s,
            %(cwe)s, %(description)s, %(exploitAvailable)s, %(exploitabilityEase)s,
            %(exploitedByMalware)s, %(fName)s, %(ip)s, %(ipString)s, %(latest)s, %(organization)s,
            %(owner)s, %(osvdbId)s, %(patchPublicationTimestamp)s, %(pluginFamily)s, %(pluginId)s,
            %(pluginModificationDate)s, %(pluginName)s, %(pluginOutput)s, %(pluginPublicationDate)s,
            %(pluginType)s, %(port)s, %(portProtocol)s, %(riskFactor)s, %(scriptVersion)s, %(seeAlso)s,
            %(service)s, %(severity)s, %(solution)s, %(source)s, %(synopsis)s, %(thoroughTests)s,
            %(vulnDetectionTimestamp)s, %(vulnPublicationTimestamp)s, %(xref)s, %(otherFindings)s
        )
        ON CONFLICT ("id") DO UPDATE SET
            "assetInventory" = excluded."assetInventory",
            "bid" = excluded."bid",
            "certId" = excluded."certId",
            "cisaKnownExploited" = excluded."cisaKnownExploited",
            "ciscoBugId" = excluded."ciscoBugId",
            "ciscoSa" = excluded."ciscoSa",
            "cpe" = excluded."cpe",
            "cveId" = excluded."cveId",
            "cveString" = excluded."cveString",
            "cvss3BaseScore" = excluded."cvss3BaseScore",
            "cvss3TemporalScore" = excluded."cvss3TemporalScore",
            "cvss3TemporalVector" = excluded."cvss3TemporalVector",
            "cvss3Vector" = excluded."cvss3Vector",
            "cvssBaseScore" = excluded."cvssBaseScore",
            "cvssScoreRationale" = excluded."cvssScoreRationale",
            "cvssScoreSource" = excluded."cvssScoreSource",
            "cvssTemporalScore" = excluded."cvssTemporalScore",
            "cvssTemporalVector" = excluded."cvssTemporalVector",
            "cvssVector" = excluded."cvssVector",
            "cwe" = excluded."cwe",
            "description" = excluded."description",
            "exploitAvailable" = excluded."exploitAvailable",
            "exploitabilityEase" = excluded."exploitabilityEase",
            "exploitedByMalware" = excluded."exploitedByMalware",
            "fName" = excluded."fName",
            "ipId" = excluded."ipId",
            "ipString" = excluded."ipString",
            "latest" = excluded."latest",
            "organizationId" = excluded."organizationId",
            "owner" = excluded."owner",
            "osvdbId" = excluded."osvdbId",
            "patchPublicationTimestamp" = excluded."patchPublicationTimestamp",
            "pluginFamily" = excluded."pluginFamily",
            "pluginId" = excluded."pluginId",
            "pluginModificationDate" = excluded."pluginModificationDate",
            "pluginName" = excluded."pluginName",
            "pluginOutput" = excluded."pluginOutput",
            "pluginPublicationDate" = excluded."pluginPublicationDate",
            "pluginType" = excluded."pluginType",
            "port" = excluded."port",
            "portProtocol" = excluded."portProtocol",
            "riskFactor" = excluded."riskFactor",
            "scriptVersion" = excluded."scriptVersion",
            "seeAlso" = excluded."seeAlso",
            "service" = excluded."service",
            "severity" = excluded."severity",
            "solution" = excluded."solution",
            "source" = excluded."source",
            "synopsis" = excluded."synopsis",
            "thoroughTests" = excluded."thoroughTests",
            "vulnDetectionTimestamp" = excluded."vulnDetectionTimestamp",
            "vulnPublicationTimestamp" = excluded."vulnPublicationTimestamp",
            "xref" = excluded."xref",
            "otherFindings" = excluded."otherFindings"
        RETURNING "id"
        """)

        # Extract values from orgObj
        
        cur.execute(insert_query, vuln_scan_obj)
        vuln_scan_id = cur.fetchone()[0]

        conn.commit()
        cur.close()
        return vuln_scan_id

    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        LOGGER.error(f"{vuln_scan_obj.get('id')} failed to save")
        return None
    
def pull_vuln_scans(org_id_dict):
    orgs_to_pull  = ['DOI', 'DHS']
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    mdl_conn = mdl_staging_connect()
    date_10_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=45)

    collection = cyhy_db["vuln_scans"]  
    query = {
        "owner": {"$in":orgs_to_pull},
        "time": {"$gte": date_10_days_ago}
    }
    cyhy_vuln_scan_data = collection.find(query)

    for vuln in cyhy_vuln_scan_data:
        try:
            ip_id = None
            if vuln.get('ip',None) is not None:
                ip_id = saveIpToMdl(mdl_conn, {
                    "ip":vuln.get('ip',None),
                    "organizationId":org_id_dict[vuln.get('owner')]
                })
            cve_id = None
            if vuln.get('cve',None) is not None:
                cve_id = saveCveToMdl(
                    mdl_conn,
                    {'name':vuln.get('cve')}
                )
                vuln_id = str(get_value_and_delete(vuln, '_id'))
                vuln['snapshots'] = [str(obj_id) for obj_id in vuln.get('snapshots', [])]
                vuln_obj = {
                    'id': vuln_id,
                    'assetInventory': get_value_and_delete(vuln, 'asset_inventory'),
                    'bid': get_value_and_delete(vuln, 'bid'),
                    'certId': get_value_and_delete(vuln, 'cert'),
                    'cisaKnownExploited': get_value_and_delete(vuln, 'cisa-known-exploited'),
                    'ciscoBugId': get_value_and_delete(vuln, 'cisco-bug-id'),
                    'ciscoSa': get_value_and_delete(vuln, 'cisco-sa'),
                    'cpe': get_value_and_delete(vuln, 'cpe'),
                    'cve': None if cve_id is None else cve_id,
                    'cveString': get_value_and_delete(vuln, 'cve'),
                    'cvss3BaseScore': get_value_and_delete(vuln, 'cvss3_base_score'),
                    'cvss3TemporalScore': get_value_and_delete(vuln, 'cvss3_temporal_score'),
                    'cvss3TemporalVector': get_value_and_delete(vuln, 'cvss3_temporal_vector'),
                    'cvss3Vector': get_value_and_delete(vuln, 'cvss3_vector'),
                    'cvssBaseScore': get_value_and_delete(vuln, 'cvss_base_score'),
                    'cvssScoreRationale': get_value_and_delete(vuln, 'cvss_score_rationale'),
                    'cvssScoreSource': get_value_and_delete(vuln, 'cvss_score_source'),
                    'cvssTemporalScore': get_value_and_delete(vuln, 'cvss_temporal_score'),
                    'cvssTemporalVector': get_value_and_delete(vuln, 'cvss_temporal_vector'),
                    'cvssVector': get_value_and_delete(vuln, 'cvss_vector'),
                    'cwe': get_value_and_delete(vuln, 'cwe'),
                    'description': get_value_and_delete(vuln, 'description'),
                    'exploitAvailable': get_value_and_delete(vuln, 'exploit_available'),
                    'exploitabilityEase': get_value_and_delete(vuln, 'exploit_ease'),
                    'exploitedByMalware': get_value_and_delete(vuln, 'exploited_by_malware'),
                    'fName': get_value_and_delete(vuln, 'fname'),
                    'ip': None if ip_id is None else ip_id,
                    'ipString': get_value_and_delete(vuln, 'ip'),
                    'latest': get_value_and_delete(vuln, 'latest'),
                    'organization': None if org_id_dict.get(vuln.get('owner',"")) is None else org_id_dict.get(vuln.get('owner',"")),  # Assuming org_id_dict maps 'owner' to 'org_id'
                    'owner': get_value_and_delete(vuln, 'owner'),
                    'osvdbId': get_value_and_delete(vuln, 'osvdb'),
                    'patchPublicationTimestamp': get_value_and_delete(vuln, 'patch_publication_date'),
                    'pluginFamily': get_value_and_delete(vuln, 'plugin_family'),
                    'pluginId': get_value_and_delete(vuln, 'plugin_id'),
                    'pluginModificationDate': get_value_and_delete(vuln, 'plugin_modification_date'),
                    'pluginName': get_value_and_delete(vuln, 'plugin_name'),
                    'pluginOutput': get_value_and_delete(vuln, 'plugin_output'),
                    'pluginPublicationDate': get_value_and_delete(vuln, 'plugin_publication_date'),
                    'pluginType': get_value_and_delete(vuln, 'plugin_type'),
                    'port': get_value_and_delete(vuln, 'port'),
                    'portProtocol': get_value_and_delete(vuln, 'protocol'),
                    'riskFactor': get_value_and_delete(vuln, 'risk_factor'),
                    'scriptVersion': get_value_and_delete(vuln, 'script_version'),
                    'seeAlso': get_value_and_delete(vuln, 'see_also'),
                    'service': get_value_and_delete(vuln, 'service'),
                    'severity': get_value_and_delete(vuln, 'severity'),
                    'solution': get_value_and_delete(vuln, 'solution'),
                    'source': get_value_and_delete(vuln, 'source'),
                    'synopsis': get_value_and_delete(vuln, 'synopsis'),
                    'thoroughTests': get_value_and_delete(vuln, 'thorough_tests'),
                    'vulnDetectionTimestamp': get_value_and_delete(vuln, 'time'),
                    'vulnPublicationTimestamp': get_value_and_delete(vuln, 'vuln_publication_date'),
                    'xref': get_value_and_delete(vuln, 'xref'),
                    'otherFindings': psycopg2.extras.Json(vuln)
                }
                saveVulnScan(mdl_conn, vuln_obj)
        except Exception as e:
            print(f"Error saving vuln_scan to mdl: {e}")
            
def saveHost(conn, host_obj):
    try:
        # Create a cursor object using the connection
        cur = conn.cursor()

        # Define the insert/update query using SQL template
        insert_query = sql.SQL("""
            INSERT INTO host (
                "id", "ipString", "ipId", "updatedTimestamp", "latestNetscan1Timestamp",
                "latestNetscan2Timestamp", "latestVulnscanTimestamp", "latestPortscanTimestamp",
                "latestScanCompletionTimestamp", "locationLongitude", "locationLatitude",
                "priority", "nextScanTimestamp", "rand", "currStage", "hostLive", "hostLiveReason",
                "status", "organizationId"
            ) VALUES (
                %(id)s, %(ipString)s, %(ipId)s, %(updatedTimestamp)s, %(latestNetscan1Timestamp)s,
                %(latestNetscan2Timestamp)s, %(latestVulnscanTimestamp)s, %(latestPortscanTimestamp)s,
                %(latestScanCompletionTimestamp)s, %(locationLongitude)s, %(locationLatitude)s,
                %(priority)s, %(nextScanTimestamp)s, %(rand)s, %(currStage)s, %(hostLive)s,
                %(hostLiveReason)s, %(status)s, %(organizationId)s
            ) ON CONFLICT ("id") DO UPDATE SET
                "ipString" = excluded."ipString",
                "ipId" = excluded."ipId",
                "updatedTimestamp" = excluded."updatedTimestamp",
                "latestNetscan1Timestamp" = excluded."latestNetscan1Timestamp",
                "latestNetscan2Timestamp" = excluded."latestNetscan2Timestamp",
                "latestVulnscanTimestamp" = excluded."latestVulnscanTimestamp",
                "latestPortscanTimestamp" = excluded."latestPortscanTimestamp",
                "latestScanCompletionTimestamp" = excluded."latestScanCompletionTimestamp",
                "locationLongitude" = excluded."locationLongitude",
                "locationLatitude" = excluded."locationLatitude",
                "priority" = excluded."priority",
                "nextScanTimestamp" = excluded."nextScanTimestamp",
                "rand" = excluded."rand",
                "currStage" = excluded."currStage",
                "hostLive" = excluded."hostLive",
                "hostLiveReason" = excluded."hostLiveReason",
                "status" = excluded."status",
                "organizationId" = excluded."organizationId"
        """)

        # Execute the insert/update query
        cur.execute(insert_query, host_obj)
        # Fetch the inserted/updated host_id
        new_host_id = host_obj.get('id',None)
        # Commit the transaction
        conn.commit()
        # Close the cursor
        cur.close()

        return new_host_id

    except (Exception, psycopg2.DatabaseError) as err:
        # Handle exceptions
        print(f"Error saving host to database: {err}")
        conn.rollback()  # Rollback changes in case of error
        cur.close()
        return None

def pull_hosts(org_id_dict):
    orgs_to_pull  = ['DOI', 'DHS']
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    mdl_conn = mdl_staging_connect()
    date_10_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=45)

    collection = cyhy_db["hosts"]  
    query = {
        "owner": {"$in":orgs_to_pull},
        "last_change": {"$gte": date_10_days_ago}
    }
    cyhy_hosts_data = collection.find(query)

    for host in cyhy_hosts_data:
        try:
            ip_id = None
            if host.get('ip',None) is not None:
                ip_id = saveIpToMdl(mdl_conn, {
                    "ip":host.get('ip',None),
                    "organizationId":org_id_dict[host.get('owner')]
                })

            host_obj = {
                'id': host.get('_id', None),
                'ipString': host.get('ip', None),
                'ipId': None if ip_id is None else ip_id,
                'updatedTimestamp': host.get('last_change', None),
                'latestNetscan1Timestamp': host.get('latest_scan', {}).get('NETSCAN1',None),
                'latestNetscan2Timestamp': host.get('latest_scan', {}).get('NETSCAN2', None),
                'latestVulnscanTimestamp': host.get('latest_scan', {}).get('VULNSCAN', None),
                'latestPortscanTimestamp': host.get('latest_scan', {}).get('PORTSCAN', None),
                'latestScanCompletionTimestamp': host.get('latest_scan', {}).get('DONE', None),
                'locationLongitude': host.get('loc', [None,None])[1],
                'locationLatitude': host.get('loc', [None,None])[0],
                'priority': host.get('priority', None),
                'nextScanTimestamp': host.get('next_scan', None),
                'rand': host.get('r', None),
                'currStage': host.get('stage', None),
                'hostLive': host.get('state', {}).get('up',None),
                'hostLiveReason': host.get('state', {}).get('reason',None),
                'status': host.get('status', None),
                'organizationId': None if org_id_dict.get(host.get('owner',"")) is None else org_id_dict.get(host.get('owner',""))
            }
            saveHost(mdl_conn, host_obj)


        except Exception as e:
            print(f"Error saving host to mdl: {e}")

def saveTicket(conn, ticket_obj):
    try:
        cur = conn.cursor()

        insert_query = sql.SQL("""
            INSERT INTO ticket (
                id, "cveString", "cveId", cvss_base_score, cvss_version, "kevId", "vulnName",
                "cvssScoreSource", "cvssSeverity", "vprScore", "falsePositive", "ipString",
                "ipId", "updatedTimestamp", "locationLongitude", "locationLatitude",
                "foundInLatestHostScan", "organizationId", "vulnPort", "portProtocol",
                "snapshotsBool", "vulnSource", "vulnSourceId", "closedTimestamp",
                "openedTimestamp"
            ) VALUES (
                %(id)s, %(cveString)s, %(cveId)s, %(cvss_base_score)s, %(cvss_version)s,
                %(kevId)s, %(vulnName)s, %(cvssScoreSource)s, %(cvssSeverity)s,
                %(vprScore)s, %(falsePositive)s, %(ipString)s, %(ipId)s,
                %(updatedTimestamp)s, %(locationLongitude)s, %(locationLatitude)s,
                %(foundInLatestHostScan)s, %(organizationId)s, %(vulnPort)s,
                %(portProtocol)s, %(snapshotsBool)s, %(vulnSource)s, %(vulnSourceId)s,
                %(closedTimestamp)s, %(openedTimestamp)s
            ) ON CONFLICT (id) DO UPDATE SET
                "cveString" = EXCLUDED."cveString",
                "cveId" = EXCLUDED."cveId",
                cvss_base_score = EXCLUDED.cvss_base_score,
                cvss_version = EXCLUDED.cvss_version,
                "kevId" = EXCLUDED."kevId",
                "vulnName" = EXCLUDED."vulnName",
                "cvssScoreSource" = EXCLUDED."cvssScoreSource",
                "cvssSeverity" = EXCLUDED."cvssSeverity",
                "vprScore" = EXCLUDED."vprScore",
                "falsePositive" = EXCLUDED."falsePositive",
                "ipString" = EXCLUDED."ipString",
                "ipId" = EXCLUDED."ipId",
                "updatedTimestamp" = EXCLUDED."updatedTimestamp",
                "locationLongitude" = EXCLUDED."locationLongitude",
                "locationLatitude" = EXCLUDED."locationLatitude",
                "foundInLatestHostScan" = EXCLUDED."foundInLatestHostScan",
                "organizationId" = EXCLUDED."organizationId",
                "vulnPort" = EXCLUDED."vulnPort",
                "portProtocol" = EXCLUDED."portProtocol",
                "snapshotsBool" = EXCLUDED."snapshotsBool",
                "vulnSource" = EXCLUDED."vulnSource",
                "vulnSourceId" = EXCLUDED."vulnSourceId",
                "closedTimestamp" = EXCLUDED."closedTimestamp",
                "openedTimestamp" = EXCLUDED."openedTimestamp"
            RETURNING id
        """)
        # Execute the insert/update query
        cur.execute(insert_query, ticket_obj)
        # Fetch the inserted/updated host_id
        new_ticket_id = cur.fetchone()[0]
        # Commit the transaction
        conn.commit()
        # Close the cursor
        cur.close()

        return new_ticket_id

    except (Exception, psycopg2.DatabaseError) as err:
        # Handle exceptions
        print(f"Error saving ticket to database: {err}")
        conn.rollback()  # Rollback changes in case of error
        cur.close()
        return None

def saveEvent(conn, event_obj):
    try:
        cur = conn.cursor()
        insert_query = sql.SQL("""
        INSERT INTO ticket_event (
            "reference", "vulnScanId", "action", "reason", "eventTimestamp", "delta", "ticketId"
        ) VALUES (
            %(reference)s, %(vulnScanId)s, %(action)s, %(reason)s, %(eventTimestamp)s, %(delta)s, %(ticketId)s
        ) ON CONFLICT ("eventTimestamp", "action", "ticketId") DO UPDATE SET
            "reference" = EXCLUDED."reference",
            "vulnScanId" = EXCLUDED."vulnScanId",
            "reason" = EXCLUDED."reason",
            "delta" = EXCLUDED."delta"             
        """)

        # Execute the insert/update query
        cur.execute(insert_query, event_obj)
        # Fetch the inserted/updated host_id
        new_event_id = cur.fetchone()[0]
        # Commit the transaction
        conn.commit()
        # Close the cursor
        cur.close()

        return new_event_id
    except (Exception, psycopg2.DatabaseError) as err:
        # Handle exceptions
        print(f"Error saving event to database: {err}")
        conn.rollback()  # Rollback changes in case of error
        cur.close()
        return None

def pull_tickets(org_id_dict):
    orgs_to_pull  = ['DOI', 'DHS']
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    mdl_conn = mdl_staging_connect()
    date_10_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=45)

    collection = cyhy_db["tickets"]  
    query = {
        "owner": {"$in":orgs_to_pull},
        "last_change": {"$gte": date_10_days_ago}
    }
    cyhy_tickets_data = collection.find(query)

    for ticket in cyhy_tickets_data:
        ip_id = None
        if ticket.get('ip',None) is not None:
            ip_id = saveIpToMdl(mdl_conn, {
                "ip":ticket.get('ip',None),
                "organizationId":org_id_dict[ticket.get('owner')]
            })
        cve_id = None
        if ticket.get('details',{}).get('cve',None) is not None:
            cve_id = saveCveToMdl(
                mdl_conn,
                {'name':ticket.get('cve')}
            )

        ticket_obj = {
            'id': str(ticket.get('_id')),
            'cveString': ticket.get('details', {}).get('cve',None),
            'cveId': None if cve_id is None else cve_id,
            'cvss_base_score': ticket.get('details', {}).get('cvss_base_score',None),
            'cvss_version': None,
            # TODO Link Kev once they are added
            'kevId': None,
            'vulnName': ticket.get('details', {}).get('name',None),
            'cvssScoreSource': ticket.get('details', {}).get('score_source',None),
            'cvssSeverity': ticket.get('details', {}).get('severity',None),
            'vprScore': None,
            'falsePositive': ticket.get('false_positive',None),
            'ipString': ticket.get('ip',None),
            'ipId': None if ip_id is None else ip_id,
            'updatedTimestamp': ticket.get('last_changed',None),
            'locationLongitude': ticket.get('loc', [None,None])[1],
            'locationLatitude': ticket.get('loc', [None,None])[0],
            'foundInLatestHostScan': ticket.get('open',None),
            'organizationId': None if org_id_dict.get(ticket.get('owner',"")) is None else org_id_dict.get(ticket.get('owner',"")),
            'vulnPort': ticket.get('port', None),
            'portProtocol': ticket.get('protocol', None),
            'snapshotsBool': True if 'snapshots' in ticket and len(ticket['snapshots']) > 0 else False,
            'vulnSource': ticket.get('source', None),
            'vulnSourceId': ticket.get('source_id', None),
            'closedTimestamp': ticket.get('time_closed', None),
            'openedTimestamp': ticket.get('time_opened', None)
        }
        ticket_id = saveTicket(mdl_conn, ticket_obj)

        for event in ticket.get('events', []):
            try:
                event_obj = {
                    'reference': str(event.get('reference', None)),
                    'vulnScanId': str(event.get('reference', None)),
                    'action': event.get('action', None),
                    'reason': event.get('reason', None),
                    'eventTimestamp': event.get('time', None),
                    'delta': event.get('delta', []),
                    'ticketId': ticket_id
                }
                print(event_obj)

                saveEvent(mdl_conn, event_obj)
            except Exception as e:
                LOGGER.error(f'Unable to save event')

def savePortScan(conn, port_scan_obj):
    try:
        cur = conn.cursor()
        insert_query = sql.SQL("""
        INSERT INTO port_scan (
            "id", "ipString", "ipId", "organizationId", "latest", "port", "protocol",
            "reason", "service", "serviceName", "serviceConfidence", "serviceMethod",
            "source", "state", "timeScanned"
        ) VALUES (
            %(id)s, %(ipString)s, %(ipId)s, %(organizationId)s, %(latest)s, %(port)s, %(protocol)s,
            %(reason)s, %(service)s, %(serviceName)s, %(serviceConfidence)s, %(serviceMethod)s,
            %(source)s, %(state)s, %(timeScanned)s
        ) ON CONFLICT ("id") DO UPDATE SET
            "ipString" = EXCLUDED."ipString",
            "ipId" = EXCLUDED."ipId",
            "organizationId" = EXCLUDED."organizationId",
            "latest" = EXCLUDED."latest",
            "port" = EXCLUDED."port",
            "protocol" = EXCLUDED."protocol",
            "reason" = EXCLUDED."reason",
            "service" = EXCLUDED."service",
            "serviceName" = EXCLUDED."serviceName",
            "serviceConfidence" = EXCLUDED."serviceConfidence",
            "serviceMethod" = EXCLUDED."serviceMethod",
            "source" = EXCLUDED."source",
            "state" = EXCLUDED."state",
            "timeScanned" = EXCLUDED."timeScanned"
            RETURNING id
    """)

        # Execute the insert/update query
        cur.execute(insert_query, port_scan_obj)
        # Fetch the inserted/updated host_id
        new_event_id = cur.fetchone()[0]
        # Commit the transaction
        conn.commit()
        # Close the cursor
        cur.close()

        return new_event_id
    except (Exception, psycopg2.DatabaseError) as err:
        # Handle exceptions
        print(f"Error saving port_scan to database: {err}")
        conn.rollback()  # Rollback changes in case of error
        cur.close()
        return None

def pull_port_scans(org_id_dict):
    orgs_to_pull  = ['DOI', 'DHS']
    LOGGER.info("Connecting to Mongo DB")
    cyhy_db = mongo_connect()
    LOGGER.info("Connection successful")
    mdl_conn = mdl_staging_connect()
    date_10_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=45)

    collection = cyhy_db["port_scans"]  
    query = {
        "owner": {"$in":orgs_to_pull},
        "time": {"$gte": date_10_days_ago}
    }
    cyhy_port_scan_data = collection.find(query)

    for port_scan in cyhy_port_scan_data:
        ip_id = None
        if port_scan.get('ip',None) is not None:
            ip_id = saveIpToMdl(mdl_conn, {
                "ip":port_scan.get('ip',None),
                "organizationId":org_id_dict[port_scan.get('owner')]
            })
        port_scan_obj = {
            'id':str(port_scan.get('_id', None)),
            'ipString': port_scan.get('ip', None),
            'ipId':None if ip_id is None else ip_id,
            'organizationId': None if org_id_dict.get(port_scan.get('owner',"")) is None else org_id_dict.get(port_scan.get('owner',"")),
            'latest':port_scan.get('latest', None),
            'port': port_scan.get('port', None),
            'protocol': port_scan.get('protocol', None),
            'reason': port_scan.get('reason', None),
            'service': psycopg2.extras.Json(port_scan.get('service', None)),
            'serviceName': port_scan.get('service', {}).get('name', None),
            'serviceConfidence': port_scan.get('service', None).get('conf', None),
            'serviceMethod': port_scan.get('service', None).get('method', None),
            'source': port_scan.get('source', None),
            'state': port_scan.get('state', None),
            'timeScanned': port_scan.get('time', None),
        }   

        savePortScan(mdl_conn, port_scan_obj)


def main():
    """Connect to CyHy DB and dmz datalake with cyhy data."""
    pull_requests()
    org_id_dict = query_organizations()
    # pull_vuln_scans(org_id_dict)
    # pull_hosts(org_id_dict)
    # pull_tickets(org_id_dict)
    # pull_port_scans(org_id_dict)


if __name__ == "__main__":
    main()
