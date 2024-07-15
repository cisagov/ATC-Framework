"""Scan to track Xpanse alerts and incidents in the P&E database.

Usage:
  xpanse_alert_pull.py [--orgs=ORG_LIST] [--last_modified=MOD_TIME] [--log-level=LEVEL]

Options:
  -h --help                         Show this message.
  -o --orgs=ORG_LIST                A semicolon-separated list of Xpanse business_units.
                                    If not specified, data will be gathered for all business_units.
                                    Orgs in the list must match the names in Xpanse. E.g. Culberson County, Texas; DHS - Citizenship and Immigration Services (CIS) - CISA
                                    [default: all]
  -m --last_modified=MOD_TIME       An integer in timestamp epoch milliseconds.
                                    Scan will pull all alerts and assets updated since the provided time.
                                    If not specified, data will be gathered for all assets and alerts. E.g. 1696996800000
                                    [default: all_time]
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
"""

# Standard Python Libraries
import datetime
import json
import logging
import sys
from typing import Any, Dict

# Third-Party Libraries
from _version import __version__
from data.pe_db.db_query_source import (  # api_pull_xpanse_vulns,
    api_xpanse_alert_insert,
    get_linked_xpanse_business_units,
)
import docopt
import pytz
import requests
from schema import And, Or, Schema, SchemaError, Use

# cisagov Libraries
import pe_reports
from pe_reports.data.config import staging_config

API_DIC = staging_config(section="xpanse")
xpanse_url = "https://api-cisa.crtx.federal.paloaltonetworks.com/public_api/"
api_key = API_DIC.get("api_key")
auth_id = API_DIC.get("auth_id")

LOGGER = logging.getLogger(__name__)


# def pull_asset_data(xpanse_asset_id_list=[]):
#     """Pull asset data from the Xpanse API."""
#     assets = []

#     url = xpanse_url + "v1/assets/get_asset_internet_exposure"
#     request_data = {"asm_id_list": xpanse_asset_id_list}

#     payload = json.dumps({"request_data": request_data})

#     headers = {
#         "x-xdr-auth-id": auth_id,
#         "Authorization": api_key,
#         "Content-Type": "application/json",
#     }

#     response = requests.request("POST", url, headers=headers, data=payload)

#     resp_dict = response.json()

#     for asset in resp_dict["reply"]["details"]:
#         asset_dict = format_asset(asset)
#         assets.append(asset_dict)

#     return assets
#     #   save_asset(asset_dict)


def pull_alerts_data(linked_org_list, business_units_list=[]):
    """Pull alerts data from the Xpanse API."""
    url = xpanse_url + "v2/alerts/get_alerts_multi_events"
    
    if len(business_units_list) == 0:
        business_units_list = list(map(lambda d: d['entity_name'], linked_org_list))

    for org in business_units_list:
        request_data = {"use_page_token": True}
        filters = []
        LOGGER.info("Running Xpanse alert pull on %s", org)
        filters.append(
            {"field": "business_units_list", "operator": "in", "value": [org]}
        )

        # TODO maybe change this to be creation time
        # if last_modified != "all_time":
        #     filters.append({
        #         "field": ""
        #     })

        if len(filters) > 0:
            request_data["filters"] = filters

        payload = json.dumps({"request_data": request_data})

        headers = {
            "x-xdr-auth-id": auth_id,
            "Authorization": api_key,
            "Content-Type": "application/json",
        }
        try:
            response = requests.request("POST", url, headers=headers, data=payload)
            resp_dict = response.json()

            page_token = resp_dict["reply"]["next_page_token"]
            LOGGER.info(
                "The current org has %s alerts", resp_dict["reply"]["total_count"]
            )

            formatted_alerts = format_alerts(resp_dict["reply"]["alerts"])
            
            for alert in formatted_alerts:
                api_xpanse_alert_insert(alert)

            while page_token is not None:
                request_data = {"next_page_token": page_token}

                payload = json.dumps({"request_data": request_data})

                response = requests.request("POST", url, headers=headers, data=payload)
                resp_dict = response.json()

                page_token = resp_dict["reply"]["next_page_token"]

                formatted_alerts = format_alerts(resp_dict["reply"]["alerts"])
                for alert in formatted_alerts:
                    api_xpanse_alert_insert(alert)

            LOGGER.info("Done Xpanse alert pull on %s", org)
        except Exception as e:
            LOGGER.error("Error querying assets for %s: %s.", org, e)


# def format_asset(asset):
#     """Format Xpanse asset to match db tables."""
#     asset_dict = {
#         "asm_id": asset.get("asm_ids", None),
#         "asset_name": asset.get("name", None),
#         "asset_type": asset.get("type", None),
#         "last_observed": asset.get("last_observed", None),
#         "first_observed": asset.get("first_observed", None),
#         "externally_detected_providers": asset.get(
#             "externally_detected_providers", None
#         ),
#         "created": asset.get("created", None),
#         "ips": asset.get("ips", None),
#         "active_external_services_types": asset.get(
#             "active_external_services_types", None
#         ),
#         "domain": asset.get("domain", None),
#         "certificate_issuer": asset.get("certificate_issuer", None),
#         "certificate_algorithm": asset.get("certificate_algorithm", None),
#         "certificate_classifications": asset.get("certificate_classifications", None),
#         "resolves": asset.get("resolves", None),
#         "top_level_asset_mapper_domain": asset["details"].get(
#             "topLevelAssetMapperDomain", None
#         ),
#         "domain_asset_type": asset["details"].get("domainAssetType", None),
#         "is_paid_level_domain": asset["details"].get("isPaidLevelDomain", None),
#         "domain_details": asset["details"].get("domainDetails", None),
#         "dns_zone": asset.get("dnsZone", None),
#         "latest_sampled_ip": asset.get("latestSampledIp", None),
#         "recent_ips": asset.get("recentIps", None),
#         "external_services": asset.get("external_services", None),
#         "externally_inferred_vulnerability_score": asset.get(
#             "externally_inferred_vulnerability_score", None
#         ),
#         "externally_inferred_cves": asset.get("externally_inferred_cves", None),
#         "explainers": asset.get("explainers", None),
#         "tags": asset.get("tags", None),
#     }

    # return asset_dict


def format_alerts(alerts):
    """Format Xpanse alerts to match db tables."""
    alert_services_dict = {}
    service_ids = []
    for alert in alerts:
        try:
            service_ids += alert.get('service_ids', []) 
            alert_services_dict[alert['alert_id']] = alert.get('service_ids', [])
        except:
            continue

    services = []
    max_n = 5000
    if service_ids is not None:
        service_id_chunks = [
            service_ids[i : i + max_n] for i in range(0, len(service_ids), max_n)
        ]

        for service_chunk in service_id_chunks:
            max_retries = 3
            retry_delay = 5 
            for retry_count in range(max_retries):
                try:
                    service_response = pull_service_data(service_chunk)
                    if service_response is not None:
                        break
                except Exception as e:
                    # Log the error message
                    LOGGER.error(f"Error querying services: {e}")

                    # If it's not the last retry, wait for the retry_delay before retrying
                    if retry_count < max_retries - 1:
                        LOGGER.info("Retrying...")
                        time.sleep(retry_delay)
                    else:
                        # If it's the last retry, set it to None and it will skip to the next chunk
                        service_response = None
                        

            if service_response is None:
                continue
            for service_obj in service_response:
                cves = []
                if service_obj["details"].get("inferredCvesObserved", None) is not None:
                    for cve in service_obj["details"].get("inferredCvesObserved", None):
                        cves.append(
                            (
                                {
                                    "cve_id": cve["inferredCve"]["cveId"],
                                    "cvss_score_v2": cve["inferredCve"].get(
                                        "cvssScoreV2", None
                                    ),
                                    "cve_severity_v2": cve["inferredCve"].get(
                                        "cveSeverityV2", None
                                    ),
                                    "cvss_score_v3": cve["inferredCve"].get(
                                        "cvssScoreV3", None
                                    ),
                                    "cve_severity_v3": cve["inferredCve"].get(
                                        "cveSeverityV3", None
                                    ),
                                },
                                {
                                    "inferred_cve_match_type": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("inferredCveMatchType", None),
                                    "product": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("product", None),
                                    "confidence": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("confidence", None),
                                    "vendor": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("vendor", None),
                                    "version_number": cve["inferredCve"][
                                        "inferredCveMatchMetadata"
                                    ].get("version", None),
                                    "activity_status": cve.get(
                                        "activityStatus", None
                                    ),
                                    "first_observed": cve.get(
                                        "firstObserved", None
                                    ),
                                    "last_observed": cve.get(
                                        "lastObserved", None
                                    ),
                                },
                            )
                        )
                services.append(
                    {
                        "service_id": service_obj.get("service_id", None),
                        "service_name": service_obj.get("service_name", None),
                        "service_type": service_obj.get("service_type", None),
                        "ip_address": service_obj.get(
                            "ip_address", None
                        ),  # list of ip strings
                        "domain": service_obj.get("domain", None),  # list of ?
                        "externally_detected_providers": service_obj.get(
                            "externally_detected_providers", None
                        ),
                        "is_active": service_obj.get("is_active", None),
                        "first_observed": service_obj.get("first_observed", None),
                        "last_observed": service_obj.get("last_observed", None),
                        "port": service_obj.get("port", None),
                        "protocol": service_obj.get("protocol", None),
                        "active_classifications": service_obj.get(
                            "active_classifications", None
                        ),  # list of strings
                        "inactive_classifications": service_obj.get(
                            "inactive_classifications", None
                        ),
                        "discovery_type": service_obj.get("discovery_type", None),
                        "externally_inferred_vulnerability_score": service_obj.get(
                            "externally_inferred_vulnerability_score", None
                        ),
                        "externally_inferred_cves": service_obj.get(
                            "externally_inferred_cves", None
                        ),
                        "service_key": service_obj["details"].get("serviceKey", None),
                        "service_key_type": service_obj["details"].get(
                            "serviceKeyType", None
                        ),
                        # providerDetails
                        # certificates
                        # domains
                        # ips
                        # classifications
                        # tlsVersions
                        "cves": cves
                        # enrichedObservationSource
                        # ip_ranges
                    }
                )

    alert_list = []
    for alert in alerts:
        tags = (alert.get("tags", None),)
        business_units_list = []
        try:
            for tag in tags[0]:
                if tag.startswith("BU:"):
                    business_units_list.append(tag[3:].strip())
                    # print(business_units_list)
        except:
            business_units_list = []
            
        assets = []
        ##Uncomment to track assets
        # asset_ids = alert["asset_ids"]
        # if asset_ids is not None:
        #     asset_id_chunks = [
        #         asset_ids[i : i + max_n] for i in range(0, len(asset_ids), max_n)
        #     ]

        #     for asset_chunk in asset_id_chunks:
        #         asset_response = pull_asset_data(asset_chunk)
        #         assets += asset_response
        current_services = []
        try:
            for service in alert.get("service_ids", []):
                service_identified = next((d for d in services if d.get('service_id') == service), None) 
                if service_identified:
                    current_services.append(service_identified) 
        except:
            pass


        alert_dict = {
            "time_pulled_from_xpanse": datetime.datetime.utcnow().replace(tzinfo=pytz.utc),
            "alert_id": alert.get("alert_id", None),
            "detection_timestamp": alert.get("detection_timestamp", None),
            "alert_name": alert.get("name", None),
            # endpoint_id ???,
            "description": alert.get("description", None),
            # "endpoint_id": alert.get('endpoint_id', None),
            # "host_ip": alert.get('host_ip', None),
            "host_name": alert.get("host_name", None),
            "alert_action": alert.get("action", None),
            # user_name ??? null,
            # mac_addresses ??? null,
            # source ??? null,
            "action_pretty": alert.get("action_pretty", None),
            # category ??? null,
            # project ??? null,
            # cloud_provider ??? null,
            # resource_sub_type ??? null,
            # resource_type ??? null,
            "action_country": alert.get("action_country", None),  # list type
            # event_type ??? null,
            # is_whitelisted ??? null,
            # image_name ??? null,
            # action_local_ip ??? null,
            # action_local_port ??? null,
            # action_external_hostname ??? null,
            # action_remote_ip ??? null,
            "action_remote_port": alert.get("action_remote_port", None),  # list type
            # "matching_service_rule_id ??? null,
            "starred": alert.get("starred", None),
            "external_id": alert.get("external_id", None),
            "related_external_id": None,
            "alert_occurrence": None,
            "severity": alert.get("severity", None),
            "matching_status": alert.get("matching_status", None),
            # end_match_attempt_ts ??? null,
            "local_insert_ts": alert.get("local_insert_ts", None),
            "last_modified_ts": alert.get("last_modified_ts") if alert.get("last_modified_ts") is not None else alert.get("local_insert_ts", None),
            "case_id": alert.get("case_id", None),  
            # deduplicate_tokens ??? null,
            # filter_rule_id ??? null,
            # event_id ??? null,
            "event_timestamp": alert.get("event_timestamp", None),  # list type
            # action_local_ip_v6 ??? null,
            # action_remote_ip_v6 ??? null,
            "alert_type": alert.get("alert_type", None),
            "resolution_status": alert.get("resolution_status", None),
            "resolution_comment": alert.get("resolution_comment", None),
            # dynamic_fields ??? null,
            "tags": alert.get("tags", None),
            # malicious_urls ??? null,
            "last_observed": alert.get("last_observed", None),
            "country_codes": alert.get("country_codes", None),  # list type
            "cloud_providers": alert.get("cloud_providers", None),  # list type
            "ipv4_addresses": alert.get("ipv4_addresses", None),  # list type
            # ipv6_addresses ??? null,
            "domain_names": alert.get("domain_names", None),  # list type
            "service_ids": alert.get("service_ids", None),  # already addressed above
            # "website_ids": alert.get('website_ids', None),
            "asset_ids": alert.get("asset_ids", None),  # list type
            "certificate": alert.get("certificate", None),
            # {
            #            issuerName": "IOS-Self-Signed-Certificate-782645061",
            #            subjectName": "IOS-Self-Signed-Certificate-782645061",
            #            validNotBefore": 1398850008000,
            #            validNotAfter": 1577836800000,
            #            serialNumber": "1"
            # },
            "port_protocol": alert.get("port_protocol", None),
            # business_unit_hierarchies
            # "business_unit_hierarchies": alert.get('business_unit_hierarchies', None), #list of BUs
            # attack_surface_rule_name ??? null,
            # remediation_guidance ??? null,
            "attack_surface_rule_name": alert.get("attack_surface_rule_name", None),
            "remediation_guidance": alert.get("remediation_guidance", None),
            "asset_identifiers": alert.get(
                "asset_identifiers", None
            ),  # messy list of objects
            "business_units": business_units_list,
            "services": current_services,
            "assets": assets,
        }

        if alert_dict["external_id"] is not None:
            alert_dict["related_external_id"] = "-".join(
                alert_dict["external_id"].split("-")[:-1]
            )
            alert_dict["alert_occurrence"] = (
                int(alert_dict["external_id"].split("-")[-1]) / 2
            )
        else:
            alert_dict["related_external_id"] = None
            alert_dict["alert_occurrence"] = None

        alert_list.append(alert_dict)
    return alert_list

def pull_service_data(service_id_list):
    """Pull service info from the Xpanse API using a service_id."""
    url = xpanse_url + "v1/assets/get_external_service"
    request_data = {"service_id_list": service_id_list}

    payload = json.dumps({"request_data": request_data})

    headers = {
        "x-xdr-auth-id": auth_id,
        "Authorization": api_key,
        "Content-Type": "application/json",
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    resp_dict = response.json()

    return resp_dict.get("reply", {}).get("details", None)


def run_xpanse_scans(last_modified, orgs_list):
    """Run Xpanse scans."""
    if orgs_list != "all":
        orgs_list = orgs_list.split(";")
    else:
        orgs_list = []

    linked_org_list = get_linked_xpanse_business_units()
    
    pull_alerts_data(linked_org_list, orgs_list)
    # api_pull_xpanse_vulns(orgs_list[0], datetime.datetime(2023, 10, 10, 1, 00))

    return 1


def main():
    """Launch Xpanse scans."""
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)

    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning", "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            str: object,  # Don't care about other keys, if any
        }
    )

    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)

    # Assign validated arguments to variables
    log_level: str = validated_args["--log-level"]

    # Set up logging
    logging.basicConfig(
        filename=pe_reports.CENTRAL_LOGGING_FILE,
        filemode="a",
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S",
        level=log_level.upper(),
    )

    run_xpanse_scans(
        validated_args["--last_modified"],
        validated_args["--orgs"],
    )

def print_start_time():
    global start_time
    start_time = datetime.datetime.now()
    print(f"Script started at: {start_time}")

# Function to print the end time and calculate duration
def print_end_time():
    end_time = datetime.datetime.now()
    print(f"Script ended at: {end_time}")

    # Calculate duration
    duration = end_time - start_time

    # Convert duration to hours, minutes, seconds
    hours, remainder = divmod(duration.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    print(f"Script took {hours} hours, {minutes} minutes, and {seconds} seconds to run.")


if __name__ == "__main__":
    print_start_time()
    main()
    print_end_time()


# python3 src/pe_source/xpanse_update.py /var/www/pe-reports/src/pe_source/XPANSE_ENTITIES_2023-11-20.csv --orgs="National Science Foundation (NSF) - CISA;National Transportation Safety Board (NTSB) - CISA;National Women's Business Council (NWBC) - CISA;Natrona County, Wyoming;Net Number;New York Assembly;New York City Department of Education;New York City Department of Environmental Protection;New York City Department of Information Technology and Telecommunications (DoITT);New York City Health and Hospitals Corporation- CISA;New York City Housing Authority;New York Community Bancorp;New York Independent System Operator (NYISO);New York Life Insurance Company- CISA;New York Metropolitan Transport Authority- CISA;New York Presbyterian Hospital- CISA;New York State Department of Environmental Conservation;New York State Insurance Fund;New York State Senate;New York University (NYU)- CISA;Niagara County, New York;Niagara County, New York- CISA;Noble County, Ohio Election Infrastructure;North American Electric Reliability Corporation (NERC);Nuclear Regulatory Commission (NRC) - CISA;Nuclear Waste Technical Review Board (NWTRB) - CISA;ODNI - National Counterintelligence Center (NCSC) - CISA;OHPRS (Ohio Police Retirement System);Occupational Safety and Health Review Commission (OSHRC) - CISA;Office for People With Developmental Disabilities;Office for the Aging;Office for the Prevention of Domestic Violence;Office of Addiction Services and Supports;Office of Attorney General;Office of Congressional Workplace Rights (OCWR) - CISA;Office of Employee Relations;Office of General Services;Office of Government Ethics (OGE) - CISA;Office of Information Technology Services;Office of Medicaid Inspector General;Office of Mental Health;Office of Navajo and Hopi Indian Relocation (ONHIR) - CISA;Office of Parks, Recreation and Historic Preservation;Office of Personnel Management (OPM) - CISA;Office of State Comptroller;Office of Temporary and Disability Assistance;Office of the Director of National Intelligence (ODNI) - CISA;Office of the Federal Register (OFR) - CISA;Office of the Governor;Ohio Rural Electric Cooperatives"
# "HHS - Substance Abuse and Mental Health Services Administration (SAMHSA) [HHS_SAMHSA];HHS - Health Resources and Services Administration [HHS_HRSA];Gulf Coast Ecosystem Restoration Council [GCERC];Securities and Exchange Commission (SEC) [SEC];USDOT - Maritime Administration (MARAD) - CISA;USDOE - Office of Fossil Energy and Carbon Management (FECM) - CISA;USDOE - Office of Environmental Management (EM) - CISA;USDOE - Office of Energy Efficiency and Renewable Energy (EERE) - CISA;USDOE - National Nuclear Security Administration (NNSA) - CISA;USDOE - Energy Information Administration (EIA) - CISA;Federal Retirement Thrift Investment Board [FRTIB];Federal Trade Commission (FTC) [FTC];Federal Permitting Improvement Steering Council (FPISC) - CISA;Federal Maritime Commission (FMC) [FMC];Farm Credit System Insurance Corporation (FCSIC) - CISA;Farm Credit Administration (FCA)  - CISA;Federal Mine Safety and Health Review Commission (FMSHRC) [FMSHRC];Privacy and Civil Liberties Oversight Board (PCLOB) [PCLOB];Federal Mediation and Conciliation Service (FMCS) [FMCS];Federal Housing Finance Agency (FHFA) - CISA;Federal Labor Relations Authority (FLRA) [FLRA];Federal Communications Commission [FCC];Federal Energy Regulatory Commission (FERC) [FERC];Federal Deposit Insurance Corporation (FDIC) [FDIC];Export-Import Bank (EXIM) [EXIM];Morris K. Udall and Stewart L. Udall Foundation (UDALL) - CISA;Pension Benefit Guaranty Corporation (PBGC) [PBGC];ED - Office of Federal Student Aid (FSA) - CISA;ED - Department of Education (ED) - CISA;FRB - Federal Reserve System (FRS) [FRB];DOJ - Office of Inspector General (OIG) - CISA;DOJ - National Crime Prevention and Privacy Compact Council - CISA;DOJ - Department of Justice (DOJ) - CISA;DOJ - Coordinating Council on Juvenile Justice and Delinquency Prevention - CISA;DOJ - Bureau of Alcohol, Tobacco, Firearms and Explosives (ATF) - CISA;DOI - United States Geological Survey (USGS) - CISA;DOI - National Park Service (NPS) [DOI_NPS];DOL - Department of Labor (DOL) - CISA;DOJ - Federal Bureau of Investigation (FBI) - CISA;DOJ - Drug Enforcement Administration (DEA) - CISA;DOI - National Indian Gaming Commission (NIGC) [NIGC];DOI - Fish and Wildlife Service (FWS) [DOI_FWS];DOI - Bureau of Reclamation (BOR) [DOI_BOR];DOC - United States Census Bureau (USCB) [DOC_CENSUS];DOC - U.S. Patent and Trademark Office (USPTO) [DOC_USPTO];DOC - National Technical Information Service (NTIS) - CISA;DOC - International Trade Administration (ITA) - CISA;DOC - Department of Commerce (DOC) [DOC];DOC - Bureau of Economic Analysis (BEA) - CISA;DHS - United States Secret Service (USSS) [DHS_USSS];DHS - Federal Protective Service (FPS) - CISA;DHS - Federal Law Enforcement Training Center (FLETC) - CISA;DHS - Cybersecurity and Infrastructure Security Agency (CISA) - CISA;DHS - Citizenship and Immigration Services (CIS) [DHS_CIS];Office of Government Ethics [OGE];Equal Employment Opportunity Commission (EEOC) [EEOC];Harry S. Truman Scholarship Foundation (HTSF) - CISA;Occupational Safety and Health Review Commission (OSHRC) [OSHRC];Nuclear Waste Technical Review Board (NWTRB) [NWTRB];Nuclear Regulatory Commission (NRC) [NRC];Environmental Protection Agency (EPA) [EPA];HHS - Administration for Community Living (ACL) - CISA;HUD - Government National Mortgage Association (GNMA) - CISA;HUD - Federal Housing Administration (FHA) - CISA;HHS - Agency for Toxic Substances and Disease Registry (ATSDR) - CISA;GSA - Regulatory Information Service Center (RISC) - CISA;National Science Foundation (NSF) [NSF];Election Assistance Commission (EAC) [EAC];USDOT - U.S. Department of Transportation Office of the Secretary (OST) - CISA;USDOT - Pipeline and Hazardous Materials Safety Administration (PHMSA) - CISA;USDOS - U.S. Embassy and Consulates - CISA;USDOE - Office of Science (SC) - CISA;National Transportation Safety Board [NTSB];National Endowment for the Arts [NEA];National Council on Disability (NCD) [NCD];National Capital Planning Commission (NCPC) [NCPC];National Labor Relations Board (NLRB) [NLRB];National Credit Union Administration (NCUA) [NCUA];National Archives and Records Administration (NARA) [NARA];National Aeronautics and Space Administration (NASA) [NASA];DOT - Unified Carrier Registration Plan (UCR) - CISA;DOJ - U.S. Marshals Service (USMS) - CISA;DOC - National Oceanic and Atmospheric Administration (NOAA) - CISA;United States Interagency Council on Homelessness (USICH) [USICH];United States Agency for International Development (USAID) [USAID];United States Access Board (USAB) [USAB];USDOE - Office of Nuclear Energy (NE) [DOE];USDA - Animal & Plant Health Inspection Service (APHIS) [USDA_APHIS];USDA - Agricultural Research Service (ARS) [USDA_ARS];USAGM - U.S. Agency for Global Media (USAGM) [USAGM];DOJ - Office of Special Counsel (OSC) - CISA;Board of Governors of the Federal Reserve (FRB) - CISA;USDOT - Volpe National Transportation Systems Center - CISA;USDOT - Office of Inspector General (OIG) - CISA;USDOT - Great Lakes St. Lawrence Seaway Development Corporation (GLS) - CISA;USDOT - Federal Transit Administration (FTA) - CISA;USDOT - Federal Railroad Administration (FRA) - CISA;USDOT - Federal Aviation Administration (FAA) - CISA;USDOE - Energy Department (DOE) - CISA;USDA - United States Forest Service (USFS) - CISA;USAGM - Broadcasting Board of Governors - CISA;TREAS - United States Mint - CISA;USDOT - United States Merchant Marine Academy (USMMA) - CISA;USDOT - National Highway Traffic Safety Administration (NHTSA) - CISA;USDOT - Federal Motor Carrier Safety Administration (FMCSA) - CISA;USDOT - Federal Highway Administration (FHWA) - CISA;USDOT - Department of Transportation (DOT) - CISA;USDOS - State Department (DOS) - CISA;USDOE - Power Marketing Administration (PMA) - CISA;TREAS - Internal Revenue Service (IRS) - CISA;James Madison Memorial Fellowship Foundation (JMMFF) [JMMFF];Tennessee Valley Authority (TVA) [TVA];Department of Veterans Affairs (VA) [VA];DOJ - Federal Bureau of Prisons (BOP) - CISA;DOI - Department of the Interior (DOI) [DOI];DOI - Bureau of Land Management (BLM) [DOI_BLM];Social Security Administration (SSA) [SSA];Small Business Administration (SBA) [SBA];Selective Service System (SSS) [SSS];Denali Commission [DENALI];Railroad Retirement Board [RRB];Presidio Trust (PT) [PT];Peace Corps (PC) [PC];DOC - National Telecommunications and Information Administration (NTIA) [DOC_NTIA];DOC - National Institute of Standards and Technology (NIST) [DOC_NIST];DHS - United States Coast Guard (USCG) [USCG];Office of Navajo and Hopi Indian Relocation [ONHIR];Office of Personnel Management (OPM) [OPM];DHS - Transportation Security Administration (TSA) [DHS_TSA];DHS - Immigration and Customs Enforcement (ICE) [DHS_ICE];DHS - Federal Emergency Management Agency (FEMA) [DHS_FEMA];DHS - Department of Homeland Security [DHS];DHS - Customs and Border Protection (CBP) [DHS_CBP];Millennium Challenge Corporation (MCC) [MCC];Merit Systems Protection Board [MSPB];Marine Mammal Commission (MMC) [MMC];Court Services and Offender Supervision Agency for the District of Columbia (CSOSA) [CSOSA];International Trade Commission (USITC) [USITC];International Development Finance Corporation (DFC) [DFC];International Boundary and Water Commission (IBWC) [IBWC];Japan-U.S. Friendship Commission (JUSFC) [JUSFC];Inter-American Foundation (IAF) [IAF];HUD - Department of Housing and Urban Development [HUD];HHS - Health and Human Services Department [HHS];HHS - National Institutes of Health [HHS_NIH];HHS - Indian Health Service [HHS_IHS];HHS - Agency for Healthcare Research and Quality [HHS_AHRQ];HHS - Administration for Children and Families [HHS_ACF];HHS - Food and Drug Administration [HHS_FDA];HHS - Centers for Medicare & Medicaid Services [HHS_CMS];HHS - Centers for Disease Control and Prevention [HHS_CDC];GSA - General Services Administration (GSA) [GSA];Council of the Inspectors General on Integrity and Efficiency (CIGIE) [CIGIE];Corporation for National and Community Service (CNCS)(Americorps) [CNCS];Commodity Futures Trading Commission (CFTC) [CFTC];Committee for Purchase from People Who Are Blind or Severely Disabled (CPPBSD)(AbilityOne) - CISA;Consumer Product Safety Commission (CPSC) [CPSC];Consumer Financial Protection Bureau (CFPB) [CFPB];Commission of Fine Arts (CFA) [CFA];Civil Rights Commission (USCCR) [USCCR];Chemical Safety Board (CSB) [CSB];Armed Forces Retirement Home (AFRH) [AFRH];American Battle Monuments Commission (ABMC) [ABMC];African Development Foundation (ADF) [ADF];Advisory Council on Historic Preservation [ACHP];Administrative Conference of the United States (ACUS) [ACUS];USDA - Department of Agriculture (USDA) [USDA];Trade and Development Agency (USTDA) [USTDA];TREAS - Office of the Comptroller of the Currency (OCC) [OCC];TREAS - Financial Stability Oversight Council (FSOC) - CISA;TREAS - Department of Treasury (TREAS) [TREAS];TREAS - Bureau of Engraving and Printing (BEP) - CISA;Surface Transportation Board (STB) [STB]"