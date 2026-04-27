"""Cybersixgill API calls."""

# Standard Python Libraries
import json
import logging
import time

# Third-Party Libraries
import pandas as pd
import requests
from retry import retry

# cisagov Libraries
from pe_source.data.pe_db.config import cybersix_token

LOGGER = logging.getLogger(__name__)


def alerts_list(auth, organization_id, fetch_size, offset):
    """Get actionable alerts by ID using organization_id with optional filters."""
    # Call Cybersixgill's /actionable-alert endpoint
    url = "https://api.cybersixgill.com/alerts/actionable-alert"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {
        "organization_id": organization_id,
        "fetch_size": fetch_size,
        "offset": offset,
    }
    resp = requests.get(url, headers=headers, params=payload, timeout=60)

    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        if resp.status_code == 401:
            # Catch 401 token expired code
            LOGGER.warning(
                "Refreshing Cybersixgill API auth token due to 401 error code..."
            )
            # Tokens expire after 30m, refresh
            auth = cybersix_token()
        if resp.status_code == 400:
            # Log additional output if 400 code encountered
            LOGGER.error(
                "Received error code 400 from Cybersixgill's /actionable-alert endpoint"
            )
            LOGGER.error(resp.content)
        endpoint_name = url.split("/")[-1]
        LOGGER.warning(
            f"Retrying Cybersixgill /{endpoint_name} endpoint (code {resp.status_code}) for chunk at offset {offset} , attempt {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.get(url, headers=headers, params=payload, timeout=60)
        retry_count += 1
    # Return result
    resp = resp.json()
    return [resp, auth]


def alerts_count(organization_id):
    """Get the total read and unread actionable alerts by organization."""
    # Call Cybersixgill's /count endpoint
    url = "https://api.cybersixgill.com/alerts/actionable_alert/count"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"organization_id": organization_id}
    resp = requests.get(url, headers=headers, params=payload, timeout=60)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        endpoint_name = url.split("/")[-1]
        LOGGER.warning(
            f"Retrying Cybersixgill /{endpoint_name} endpoint (code {resp.status_code}), attmept {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.get(url, headers=headers, params=payload, timeout=60)
        retry_count += 1
    resp = resp.json()
    # Return result
    return resp


def alerts_content(organization_id, alert_id):
    """Get total alert content."""
    # Call Cybersixgill's /actionable_alert_content endpoint
    url = f"https://api.cybersixgill.com/alerts/actionable_alert_content/{alert_id}"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"organization_id": organization_id, "limit": 10000}
    content = requests.get(url, headers=headers, params=payload, timeout=60)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while content.status_code != 200 and retry_count < max_retries:
        # endpoint_name = url.split("/")[-1]
        LOGGER.warning(
            f"Retrying Cybersixgill /actionable_alert_content endpoint (code {content.status_code}), attmept {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        content = requests.get(url, headers=headers, params=payload, timeout=60)
        retry_count += 1
    content = content.json()
    try:
        content = content["content"]["items"][0]
        if "_source" in content:
            content = content["_source"]["content"]
        elif "description" in content:
            content = content["description"]
        else:
            content = ""
    except Exception as e:
        LOGGER.error("Failed getting content snip: %s", e)
        content = ""
    # Return result
    return content


def intel_post(auth, query, frm, scroll, result_size):
    """Get intel items - advanced variation."""
    # Call Cybersixgill's /intel_items endpoint
    url = "https://api.cybersixgill.com/intel/intel_items"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {
        "query": query,
        "partial_content": False,
        "results_size": result_size,
        "scroll": scroll,
        "from": frm,
        "sort": "date",
        "sort_type": "desc",
        "highlight": False,
        # "custom_highlight_start_tag": "@@mention_start@@",
        # "custom_highlight_end_tag": "@@mention_end@@",
        "recent_items": False,
        "safe_content_size": True,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=60)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        if resp.status_code == 401:
            # Catch 401 token expired code
            LOGGER.warning(
                "Refreshing Cybersixgill API auth token due to 401 error code..."
            )
            # Tokens expire after 30m, refresh
            auth = cybersix_token()
        endpoint_name = url.split("/")[-1]
        LOGGER.warning(
            f"Retrying Cybersixgill /{endpoint_name} endpoint (code {resp.status_code}), attmept {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        retry_count += 1
    # Return result
    resp = resp.json()
    return [resp, auth]


def intel_post_next(auth, scroll_id):
    """Get intel_items based on specified scroll_id."""
    url = "https://api.cybersixgill.com/intel/intel_items/next"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {
        "scroll_id": scroll_id,
        "recent_items": False,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=60)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        if resp.status_code == 401:
            # Catch 401 token expired code
            LOGGER.warning(
                "Refreshing Cybersixgill API auth token due to 401 error code..."
            )
            # Tokens expire after 30m, refresh
            auth = cybersix_token()
        LOGGER.warning(
            f"Retrying Cybersixgill /intel_items/next endpoint (code {resp.status_code}), attmept {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        retry_count += 1
    # Return result
    resp = resp.json()
    return [resp, auth]


def credential_auth(auth, params):
    """Get data about a specific CVE."""
    # Call Cybersixgill's /leaks endpoint
    url = "https://api.cybersixgill.com/credentials/leaks"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        if resp.status_code == 401:
            # Catch 401 token expired code
            LOGGER.warning(
                "Refreshing Cybersixgill API auth token due to 401 error code..."
            )
            # Tokens expire after 30m, refresh
            auth = cybersix_token()
        endpoint_name = url.split("/")[-1]
        LOGGER.warning(
            f"Retrying Cybersixgill /{endpoint_name} endpoint (code {resp.status_code}), attmept {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        retry_count += 1
    resp = resp.json()
    # Return result
    return [resp, auth]


def dve_top_cves():
    """Retrieve the top 10 CVEs for this report period."""
    # Call Cybersixgill's /enrich endpoint
    url = "https://api.cybersixgill.com/dve_enrich/enrich"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    data = json.dumps(
        {
            "filters": {
                "sixgill_rating_range": {"from": 6, "to": 10},
            },
            "results_size": 10,
            "enriched": True,
            "from_index": 0,
        }
    )
    resp = requests.post(url, headers=headers, data=data, timeout=60)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        endpoint_name = url.split("/")[-1]
        LOGGER.warning(
            f"Retrying Cybersixgill /{endpoint_name} endpoint (code {resp.status_code}), attmept {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(url, headers=headers, data=data, timeout=60)
        retry_count += 1
    resp = resp.json()
    # Sort and clean top CVE data
    result_list = resp.get("objects")
    clean_top_10_cves = []
    for result in result_list:
        cve_id = result.get("name")
        dynamic_rating = result.get("x_sixgill_info").get("rating").get("current")
        if result.get("x_sixgill_info").get("nvd").get("v3") is None:
            nvd_v3_score = None
        else:
            nvd_v3_score = (
                result.get("x_sixgill_info").get("nvd").get("v3").get("current")
            )
        nvd_base_score = "{'v2': None, 'v3': " + str(nvd_v3_score) + "}"
        summary = result.get("description").strip()
        clean_cve = {
            "cve_id": cve_id,
            "dynamic_rating": dynamic_rating,
            "nvd_base_score": nvd_base_score,
            "summary": summary,
        }
        clean_top_10_cves.append(clean_cve)
    clean_top_10_cves = sorted(
        clean_top_10_cves, key=lambda d: d["dynamic_rating"], reverse=True
    )
    # Return result
    return clean_top_10_cves


def get_sixgill_organizations():
    """Get the list of organizations."""
    # Call Cybersixgill's /organization endpoint
    url = "https://api.cybersixgill.com/multi-tenant/organization"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    orgs = requests.get(url, headers=headers, timeout=60)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while orgs.status_code != 200 and retry_count < max_retries:
        endpoint_name = url.split("/")[-1]
        LOGGER.warning(
            f"Retrying Cybersixgill /{endpoint_name} endpoint (code {orgs.status_code}), attmept {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        orgs = requests.get(url, headers=headers, timeout=60)
        retry_count += 1
    orgs = orgs.json()
    df_orgs = pd.DataFrame(orgs)
    df_orgs = df_orgs[["name", "organization_id"]]
    sixgill_dict = df_orgs.set_index("name").agg(list, axis=1).to_dict()
    # Return results
    return sixgill_dict


def org_assets(org_id):
    """Get organization assets."""
    # Call Cybersixgill's /assets endpoint
    url = f"https://api.cybersixgill.com/multi-tenant/organization/{org_id}/assets"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    payload = {"organization_id": org_id}
    resp = requests.get(url, headers=headers, params=payload, timeout=60)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        endpoint_name = url.split("/")[-1]
        LOGGER.warning(
            f"Retrying Cybersixgill /{endpoint_name} endpoint (code {resp.status_code}), attmept {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.get(url, headers=headers, params=payload, timeout=60)
        retry_count += 1
    resp = resp.json()
    # Return result
    return resp


def setNewCSGOrg(newOrgName, orgAliases, orgDomainNames, orgIP, orgExecs):
    """Set a new stakeholder name in CSG."""
    newOrganization = json.dumps(
        {
            "name": f"{newOrgName}",
            "organization_commercial_category": "customer",
            "countries": ["worldwide"],
            "industries": ["Government"],
        }
    )
    url = "https://api.cybersixgill.com/multi-tenant/organization"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": f"Bearer {cybersix_token()}",
    }
    response = requests.post(
        url, headers=headers, data=newOrganization, timeout=60
    ).json()
    newOrgID = response["id"]
    if newOrgID:
        LOGGER.info("A new org_id was created: %s", newOrgID)
        setOrganizationUsers(newOrgID)
        setOrganizationDetails(newOrgID, orgAliases, orgDomainNames, orgIP, orgExecs)
    return response


def setOrganizationUsers(org_id):
    """Set CSG user permissions at new stakeholder."""
    role1 = "5d23342df5feaf006a8a8929"
    role2 = "5d23342df5feaf006a8a8927"
    id_role1 = "610017c216948d7efa077a52"
    csg_role_id = "role_id"
    csg_user_id = "user_id"
    for user in getUserInfo():
        userrole = user[csg_role_id]
        user_id = user[csg_user_id]
        if (
            (userrole == role1)
            and (user_id != id_role1)
            or userrole == role2
            and user_id != id_role1
        ):
            url = (
                f"https://api.cybersixgill.com/multi-tenant/organization/"
                f"{org_id}/user/{user_id}?role_id={userrole}"
            )
            headers = {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
                "Authorization": f"Bearer {cybersix_token()}",
            }
            response = requests.post(url, headers=headers, timeout=60).json()
            LOGGER.info("The response is %s", response)


def setOrganizationDetails(org_id, orgAliases, orgDomain, orgIP, orgExecs):
    """Set stakeholder details at newly created.

    stakeholder at CSG portal via API.
    """
    newOrganizationDetails = json.dumps(
        {
            "organization_aliases": {"explicit": orgAliases},
            "domain_names": {"explicit": orgDomain},
            "ip_addresses": {"explicit": orgIP},
            "executives": {"explicit": orgExecs},
        }
    )
    url = f"https://api.cybersixgill.com/multi-tenant/" f"organization/{org_id}/assets"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": f"Bearer {cybersix_token()}",
    }
    response = requests.put(
        url, headers=headers, data=newOrganizationDetails, timeout=60
    ).json()
    LOGGER.info("The response is %s", response)


def getUserInfo():
    """Get all organization details from Cybersixgill via API."""
    url = "https://api.cybersixgill.com/multi-tenant/organization"
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": f"Bearer {cybersix_token()}",
    }
    response = requests.get(url, headers=headers, timeout=60).json()
    userInfo = response[1]["assigned_users"]
    return userInfo


@retry(tries=10, delay=1, logger=LOGGER)
def get_bulk_cve_resp(cve_list):
    """
    Make API call to retrieve the corresponding info for a list of CVE names (10 max).

    Args:
        cve_list: list of cve names (i.e. ['CVE-2022-123', 'CVE-2022-456'...])

    Returns:
        Raw API response for CVE list

    """
    # Call Cybersixgill's /enrich endpoint
    c6g_url = "https://api.cybersixgill.com/dve_enrich/enrich"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    body = {
        "filters": {"ids": cve_list},
        "results_size": len(cve_list),
        "from_index": 0,
    }
    resp = requests.post(c6g_url, headers=headers, json=body, timeout=60)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 5
    while resp.status_code != 200 and retry_count < max_retries:
        endpoint_name = c6g_url.split("/")[-1]
        LOGGER.warning(
            f"Retrying Cybersixgill /{endpoint_name} endpoint (code {resp.status_code}), attmept {retry_count+1} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(c6g_url, headers=headers, json=body, timeout=60)
        retry_count += 1
    resp = resp.json()
    # Return results
    return resp
