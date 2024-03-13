"""Create all api enpoints."""

# Standard Python Libraries
import csv
from datetime import datetime, timedelta
from io import TextIOWrapper
import logging
import socket
from typing import Any, List, Optional, Union
import uuid

# Third-Party Libraries
# Import api task functions
from dataAPI.tasks import (
    alerts_insert_task,
    breachdetails_view_task,
    convert_date_to_string,
    convert_uuid_to_string,
    cred_breach_intelx_task,
    cred_breach_sixgill_task,
    cred_exp_sixgill_task,
    credential_breach_vulns_task,
    credsbydate_view_task,
    cve_info_insert_task,
    cves_by_modified_date_task,
    darkweb_cves_task,
    get_dscore_pe_domain_info,
    get_dscore_pe_ip_info,
    get_dscore_vs_cert_info,
    get_dscore_vs_mail_info,
    get_dscore_was_webapp_info,
    get_fceb_status_info,
    get_iscore_pe_breach_info,
    get_iscore_pe_cred_info,
    get_iscore_pe_darkweb_info,
    get_iscore_pe_protocol_info,
    get_iscore_pe_vuln_info,
    get_iscore_vs_vuln_info,
    get_iscore_vs_vuln_prev_info,
    get_iscore_was_vuln_info,
    get_iscore_was_vuln_prev_info,
    get_kev_list_info,
    get_l_stakeholders_info,
    get_m_stakeholders_info,
    get_s_stakeholders_info,
    get_ve_info,
    get_vs_info,
    get_vw_pshtt_domains_to_run_info,
    get_xl_stakeholders_info,
    get_xpanse_vulns,
    get_xs_stakeholders_info,
    ips_insert_task,
    ips_update_from_cidr_task,
    mentions_insert_task,
    pescore_base_metrics_task,
    pescore_hist_cred_task,
    pescore_hist_darkweb_alert_task,
    pescore_hist_darkweb_ment_task,
    pescore_hist_domain_alert_task,
    shodan_vulns_task,
    sub_domains_by_org_task,
    sub_domains_table_task,
    top_cves_insert_task,
    was_vulns_task
)
from decouple import config
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import transaction
from django.db.models import F, Q
from django.forms.models import model_to_dict
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Security,
    UploadFile,
    status,
)
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.api_key import APIKeyHeader
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

# Import api database models
from home.models import (
    Alerts,
    Cidrs,
    CpeProduct,
    CpeVender,
    CredentialBreaches,
    CredentialExposures,
    Cves,
    CyhyContacts,
    CyhyDbAssets,
    CyhyPortScans,
    DataSource,
    DomainAlerts,
    DomainPermutations,
    Mentions,
    Organizations,
    PshttResults,
    ReportSummaryStats,
    RootDomains,
    ShodanAssets,
    SubDomains,
    VwBreachcomp,
    VwBreachcompBreachdetails,
    VwBreachcompCredsbydate,
    VwCidrs,
    VwDarkwebAssetalerts,
    VwDarkwebExecalerts,
    VwDarkwebInviteonlymarkets,
    VwDarkwebMentionsbydate,
    VwDarkwebMostactposts,
    VwDarkwebPotentialthreats,
    VwDarkwebSites,
    VwDarkwebSocmediaMostactposts,
    VwDarkwebThreatactors,
    VwIpsCidrOrgInfo,
    VwIpsSubRootOrgInfo,
    VwOrgsAttacksurface,
    VwPEScoreCheckNewCVE,
    VwShodanvulnsSuspected,
    VwShodanvulnsVerified,
    WasTrackerCustomerdata,
    WeeklyStatuses,
    XpanseAlerts,
    XpanseAssets,
    XpanseBusinessUnits,
    XpanseCves,
    XpanseCveService,
    XpanseServices,
)
from jose import exceptions, jwt
from redis import asyncio as aioredis
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.status import HTTP_403_FORBIDDEN

from . import schemas
from .models import apiUser

# Setup logging
LOGGER = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
ALGORITHM = "HS256"
JWT_SECRET_KEY = config("JWT_SECRET_KEY")  # should be kept secret
JWT_REFRESH_SECRET_KEY = config("JWT_REFRESH_SECRET_KEY")  # should be kept secret

API_KEY_NAME = "access_token"
COOKIE_DOMAIN = "localtest.me"

# TODO following api_key_query was left intentionally for future development
#   to pass query to api call see issue#
# api_key_query = APIKeyQuery(name=API_KEY_NAME, auto_error=False)
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


limiter = Limiter(key_func=get_remote_address, default_limits=["5 per minute"])


async def default_identifier(request):
    """Return default identifier."""
    return request.headers.get("X-Real-IP", request.client.host)


@api_router.on_event("startup")
async def startup():
    """Start up Redis."""
    redis = aioredis.from_url(
        settings.CELERY_RESULT_BACKEND, encoding="utf-8", decode_responses=True
    )
    await FastAPILimiter.init(redis, identifier=default_identifier)


def create_access_token(
    subject: Union[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Create access token."""
    if expires_delta is not None:
        expires_date = datetime.utcnow() + expires_delta
    else:
        expires_date = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expires_date, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def create_refresh_token(
    subject: Union[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Create a refresh token."""
    if expires_delta is not None:
        expires_date = datetime.utcnow() + expires_delta
    else:
        expires_date = datetime.utcnow() + timedelta(
            minutes=REFRESH_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expires_date, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt


def userinfo(theuser):
    """Get all users in a list."""
    user_record = list(User.objects.filter(username=f"{theuser}"))

    if user_record:
        for u in user_record:
            return u.id


def userapiTokenUpdate(expiredaccessToken, user_refresh, theapiKey, user_id):
    """When api apiKey is expired a new key is created and updated in the database."""
    print(f"Got to update token {expiredaccessToken}")
    theusername = ""
    user_record = list(User.objects.filter(id=f"{user_id}"))

    # user_record = User.objects.get(id=user_id)

    for u in user_record:
        theusername = u.username
        theuserid = u.id
    LOGGER.info(f"The username is {theusername} with a user of {theuserid}")

    updateapiuseraccessToken = apiUser.objects.get(apiKey=expiredaccessToken)
    # updateapiuserrefreshToken = apiUser.objects.get(refresh_token=expiredrefreshToken)

    updateapiuseraccessToken.apiKey = f"{create_access_token(theusername)}"
    # updateapiuserrefreshToken.refresh_token = f"{create_refresh_token(theusername)}"
    # LOGGER.info(updateapiuseraccessToken.apiKey)

    updateapiuseraccessToken.save(update_fields=["apiKey"])
    # updateapiuserrefreshToken.save(update_fields=['refresh_token'])
    LOGGER.info(
        f"The user api key and refresh token have been updated from: {theapiKey} to: {updateapiuseraccessToken.apiKey}."
    )


def userapiTokenverify(theapiKey):
    """Check to see if api key is expired."""
    tokenRecords = list(apiUser.objects.filter(apiKey=theapiKey))
    user_key = ""
    user_refresh = ""
    user_id = ""

    for u in tokenRecords:
        user_refresh = u.refresh_token
        user_key = u.apiKey
        user_id = u.id
    LOGGER.info(f"The user key is {user_key}")
    LOGGER.info(f"The user refresh key is {user_refresh}")
    LOGGER.info(f"the token being verified at verify {theapiKey}")

    try:
        jwt.decode(
            theapiKey,
            config("JWT_REFRESH_SECRET_KEY"),
            algorithms=ALGORITHM,
            options={"verify_signature": False},
        )
        LOGGER.info(f"The api key was alright {theapiKey}")

    except exceptions.JWTError:
        LOGGER.warning("The access token has expired and will be updated")
        userapiTokenUpdate(user_key, user_refresh, theapiKey, user_id)


async def get_api_key(
    # api_key_query: str = Security(api_key_query),
    api_key_header: str = Security(api_key_header),
    # api_key_cookie: str = Security(api_key_cookie),
):
    """Get api key from header."""
    if api_key_header != "":
        return api_key_header

    else:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
        )


@api_router.post("/get_key", tags=["Get user api keys"])
def read_get_key(data: schemas.UserAPI):
    """Call API endpoint to get api by submitting refresh token."""
    user_key = ""
    userkey = list(apiUser.objects.filter(refresh_token=data.refresh_token))
    LOGGER.info(f"The input data requested was ***********{data.refresh_token[-10:]}")

    for u in userkey:
        user_key = u.apiKey
    return user_key


@api_router.post(
    "/signup",
    summary="Create api key and access token on user",
    tags=["Sign-up to add api_key and access token to user"],
)
def create_user(data: schemas.UserAuth):
    """Create an API User."""
    # querying database to check if user already exist
    user = userinfo(data.username)

    # TODO put logging statement here.
    print(f"The user id is {user}\n")
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this username does not exist",
        )

    theNewUser = apiUser(
        apiKey=create_access_token(data.username),
        user_id=user,
        refresh_token=create_refresh_token(data.username),
    )
    apiUser.save(theNewUser)
    return theNewUser


@api_router.post(
    "/fetch_weekly_statuses",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.WeeklyStatuses],
    tags=["List of all Weekly Statuses"],
)
def read_weekly_statuses(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get weekly statuses."""
    current_date = datetime.now()
    days_to_week_end = (4 - current_date.weekday()) % 7
    week_ending_date = current_date + timedelta(days=days_to_week_end)
    statuses = list(WeeklyStatuses.objects.filter(week_ending=week_ending_date))

    # LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return statuses
    except Exception:
        LOGGER.info("API key expired please try again")


@api_router.post(
    "/fetch_user_weekly_statuses/",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.WeeklyStatuses],
    tags=["List of user Weekly Status"],
)
def read_user_weekly_statuses(
    data: schemas.UserStatuses, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get a user weekly statuses."""
    current_date = datetime.now()
    days_to_week_end = (4 - current_date.weekday()) % 7
    week_ending_date = current_date + timedelta(days=days_to_week_end)
    statuses = list(
        WeeklyStatuses.objects.filter(
            week_ending=week_ending_date, user_status=data.user_fname
        )
    )

    # LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        return statuses
    except Exception:
        LOGGER.info("API key expired please try again")


def process_item(item):
    """Process CSV rows."""
    # TODO: Replace with the code for what you wish to do with the row of data in the CSV.
    LOGGER.info("The item is %s" % item)
    print("The item is %s" % item)


@api_router.post(
    "/orgs",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.Organization],
    tags=["List of all Organizations"],
)
def read_orgs(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all organizations."""
    orgs = list(Organizations.objects.all())

    if tokens:
        # LOGGER.info(f"The api key submitted {tokens}")
        try:
            userapiTokenverify(theapiKey=tokens)
            return orgs
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/subdomains/{root_domain_uid}",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.SubDomainBase],
    tags=["List of all Subdomains"],
)
def read_sub_domain(root_domain_uid: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all organizations."""
    # count = SubDomains.objects.all().count()
    # print(f'The count is {count}')
    # finalList = []
    # chunk_size = 1000
    # for i in range(0, count, chunk_size):
    #     records = list(SubDomains.objects.all()[i:i+chunk_size])
    #     for record in records:
    #         finalList.append(record)
    # subs = list(SubDomains.objects.all()[:999])
    subs = list(SubDomains.objects.filter(root_domain_uid=root_domain_uid))

    # orgs_df = pd.DataFrame(orgs)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            print("Got to subdomains try")
            userapiTokenverify(theapiKey=tokens)
            return subs
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/breachcomp",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.VwBreachcomp],
    tags=["List all breaches"],
)
def read_breachcomp(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all breaches."""
    breachInfo = list(VwBreachcomp.objects.all())
    print(breachInfo)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return breachInfo
        except Exception:
            LOGGER.info("API key expired please try again")

    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/breachcomp_credsbydate",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwCredsbydateTaskResp,
    tags=["Get the entire vw_breachcomp_credsbydate view."],
)
def credsbydate_view(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get the entire credsbydate view."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = credsbydate_view_task.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/breachcomp_credsbydate/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwCredsbydateTaskResp,
    tags=["Check task status for vw_breachcomp_credsbydate view query."],
)
async def credsbydate_view_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for credsbydate_view."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = credsbydate_view_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/orgs_attacksurface",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.VwOrgsAttacksurface],
    tags=["Get asset counts for an organization"],
)
def read_orgs_attacksurface(
    data: schemas.VwOrgsAttacksurfaceInput, tokens: dict = Depends(get_api_key)
):
    """Get asset counts for an organization attack surfaces."""
    print(data.organizations_uid)
    attackSurfaceInfo = list(
        VwOrgsAttacksurface.objects.filter(organizations_uid=data.organizations_uid)
    )

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return attackSurfaceInfo
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/cyhy_db_asset",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.CyhyDbAssets],
    tags=["Get cyhy assets"],
)
def read_cyhy_db_asset(
    data: schemas.CyhyDbAssetsInput, tokens: dict = Depends(get_api_key)
):
    """Get Query cyhy assets."""
    print(data.org_id)
    cyhyAssets = list(CyhyDbAssets.objects.filter(org_id=data.org_id))

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return cyhyAssets
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/cidrs",
    dependencies=[Depends(get_api_key)],
    # response_model=List[schemas.Cidrs],
    tags=["List of all CIDRS"],
)
def read_cidrs(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all CIDRS."""
    cidrs = list(VwCidrs.objects.all())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return cidrs
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/breachdetails",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwBreachDetailsTaskResp,
    tags=["Get the entire vw_breachcomp_breachdetails view."],
)
def breachdetails_view(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get the entire breachdetails view."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = breachdetails_view_task.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/breachdetails/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwBreachDetailsTaskResp,
    tags=["Check task status for vw_breachcomp_breachdetails view query."],
)
async def breachdetails_view_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for breachdetails_view."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = breachdetails_view_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/cyhy_port_scan",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.WASDataBase],
    tags=["Create new cyhy port scan data"],
)
def cyhy_port_scan_info_create(
    ports_scan_data: schemas.CyhyPortScans, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to create a record in database."""
    cyhy_ports = CyhyPortScans(**ports_scan_data.dict())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            cyhy_ports.save()
            return {"saved_customer": cyhy_ports}
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# ---------- RVA Endpoints ----------
# @api_router.post(
#     "/rva_info",
#     dependencies=[Depends(get_api_key)],
#     response_model=schemas.TaskResponse,
#     tags=["List of all VE data"],
# )
# def rva_info(ip_address: List[str], tokens: dict = Depends(get_api_key)):
#     """Call API endpoint to get all WAS data."""
#     print(ip_address)

#     # orgs_df = pd.DataFrame(orgs)

#     LOGGER.info(f"The api key submitted {tokens}")
#     if tokens:
#         task = get_rva_info.delay(ip_address)
#         return {"task_id": task.id, "status": "Processing"}
#     else:
#         return {"message": "No api key was submitted"}


# @api_router.get(
#     "/rva_info/task/{task_id}",
#     dependencies=[Depends(get_api_key)],
#     response_model=schemas.veTaskResponse,
#     tags=["Check task VE status"],
# )
# async def get_rva_task_status(task_id: str, tokens: dict = Depends(get_api_key)):
#     """Get RVA task status."""
#     task = get_rva_info.AsyncResult(task_id)

#     if task.state == "SUCCESS":
#         return {"task_id": task_id, "status": "Completed", "result": task.result}
#     elif task.state == "PENDING":
#         return {"task_id": task_id, "status": "Pending"}
#     elif task.state == "FAILURE":
#         return {"task_id": task_id, "status": "Failed", "error": str(task.result)}
#     else:
#         return {"task_id": task_id, "status": task.state}


# ---------- VE Endpoints ----------
@api_router.post(
    "/ve_info",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.TaskResponse,
    tags=["List of all VE data"],
)
def ve_info(ip_address: List[str], tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all WAS data."""
    print(ip_address)

    # orgs_df = pd.DataFrame(orgs)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        task = get_ve_info.delay(ip_address)
        return {"task_id": task.id, "status": "Processing"}
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/ve_info/task/{task_id}",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.veTaskResponse,
    tags=["Check task VE status"],
)
async def get_ve_task_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Get VE task status."""
    task = get_ve_info.AsyncResult(task_id)

    if task.state == "SUCCESS":
        return {"task_id": task_id, "status": "Completed", "result": task.result}
    elif task.state == "PENDING":
        return {"task_id": task_id, "status": "Pending"}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "Failed", "error": str(task.result)}
    else:
        return {"task_id": task_id, "status": task.state}


# ---------- VS Endpoints ----------
@api_router.post(
    "/vs_info",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.veTaskResponse,
    tags=["List of all VS data"],
)
def vs_info(cyhy_db_names: List[str], tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all WAS data."""
    print(cyhy_db_names)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        task = get_vs_info.delay(cyhy_db_names)
        return {"task_id": task.id, "status": "Processing"}
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/vs_info/task/{task_id}",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.TaskResponse,
    tags=["Check task status"],
)
async def get_task_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Get VS info task status."""
    task = get_vs_info.AsyncResult(task_id)

    if task.state == "SUCCESS":
        return {"task_id": task_id, "status": "Completed", "result": task.result}
    elif task.state == "PENDING":
        return {"task_id": task_id, "status": "Pending"}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "Failed", "error": str(task.result)}
    else:
        return {"task_id": task_id, "status": task.state}


# ---------- WAS Endpoints ----------
@api_router.post(
    "/was_info",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.WASDataBase],
    tags=["List of all WAS data"],
)
def was_info(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all WAS data."""
    was_data = list(WasTrackerCustomerdata.objects.all())

    # orgs_df = pd.DataFrame(orgs)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            return was_data
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.delete(
    "/was_info_delete/{tag}",
    dependencies=[Depends(get_api_key)],
    tags=["Delete WAS data"],
)
def was_info_delete(tag: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to delete a record in database."""
    was_data = WasTrackerCustomerdata.objects.get(tag=tag)

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            was_data.delete()
            return {"deleted_tag": tag}
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/was_info_create",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.WASDataBase],
    tags=["Create new WAS data"],
)
def was_info_create(customer: schemas.WASDataBase, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to create a record in database."""
    was_customer = WasTrackerCustomerdata(**customer.dict())

    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            was_customer.save()
            return {"saved_customer": was_customer}
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.put(
    "/was_info_update/{tag}",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.WASDataBase],
    tags=["Update WAS data"],
)
@transaction.atomic
def was_info_update(
    tag: str, customer: schemas.WASDataBase, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to create a record in database."""
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            was_data = WasTrackerCustomerdata.objects.get(tag=tag)
            updated_data = {}
            for field, value in customer.dict(exclude_unset=True).items():
                print(f"the field is {field} and the value is {value}")
                if hasattr(was_data, field) and getattr(was_data, field) != value:
                    setattr(was_data, field, value)
                    updated_data[field] = value
            was_data.save()
            return {
                "message": "Record updated successfully.",
                "updated_data": updated_data,
            }

        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.put(
    "/was_info_update/{cyhy_id}",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.WASDataBase],
    tags=["Update cyhy_port_scan data"],
)
@transaction.atomic
def cyhy_ports_scan_info_update(
    cyhy_id: str, org_scans: schemas.CyhyPortScans, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to update a record in database."""
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            scan_data = CyhyPortScans.objects.get(cyhy_id=cyhy_id)
            updated_data = {}
            for field, value in org_scans.dict(exclude_unset=True).items():
                print(f"the field is {field} and the value is {value}")
                if hasattr(scan_data, field) and getattr(scan_data, field) != value:
                    setattr(scan_data, field, value)
                    updated_data[field] = value
            scan_data.save()
            return {
                "message": "Record updated successfully.",
                "updated_data": updated_data,
            }

        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/was_upload", dependencies=[Depends(get_api_key)], tags=["Upload WAS csv file"]
)
def upload(file: UploadFile = File(...)):
    """Upload csv file from WAS."""
    f = TextIOWrapper(file.file)

    dict_reader = csv.DictReader(f)
    # dict_reader = dict_reader.fieldnames
    # dict_reader = set(dict_reader)
    col_names = dict_reader.fieldnames
    if col_names is None:
        raise HTTPException(400, detail="The CSV file does not have headers")

    col_names_set: set[str] = set(col_names)

    required_columns = [
        "org",
        "org_code",
        "root_domain",
        "exec_url",
        "aliases",
        "premium",
        "demo",
    ]
    # Check needed columns exist
    incorrect_col = []
    testtheList = [i for i in required_columns if i in col_names_set]

    try:
        if not file.filename.endswith("csv"):
            raise HTTPException(400, detail="Invalid document type")

        if len(testtheList) == len(col_names):
            for row, item in enumerate(dict_reader, start=1):
                process_item(item)
            return {"message": "Successfully uploaded %s" % file.filename}
        else:
            for col in required_columns:
                if col in col_names:
                    pass
                else:
                    incorrect_col.append(col)
            raise HTTPException(
                400,
                detail="There was a missing or"
                " incorrect column in file,"
                " to columns %s" % incorrect_col,
            )

    except ValueError:
        return {
            "message": "There was an error uploading the file at %s." % incorrect_col
        }
    except ValidationError as e:
        return {"message": "There was an error uploading the file type at %s." % e}

    finally:
        file.file.close()


# ---------- I-Score View Endpoints, Issue 570 ----------
# --- Endpoints for vw_iscore_vs_vuln view ---
@api_router.post(
    "/iscore_vs_vuln",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreVSVulnTaskResp,
    tags=["Get all VS vuln data needed for I-Score"],
)
def read_iscore_vs_vuln(
    data: schemas.VwIscoreVSVulnInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all VS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_vs_vuln_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_vs_vuln/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreVSVulnTaskResp,
    tags=["Check task status for I-Score VS vuln view."],
)
async def get_iscore_vs_vuln_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status read_iscore_vs_vuln."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_vs_vuln_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_iscore_vs_vuln_prev view ---
@api_router.post(
    "/iscore_vs_vuln_prev",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreVSVulnPrevTaskResp,
    tags=["Get all previous VS vuln data needed for I-Score"],
)
def read_iscore_vs_vuln_prev(
    data: schemas.VwIscoreVSVulnPrevInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all previous VS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_vs_vuln_prev_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_vs_vuln_prev/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreVSVulnPrevTaskResp,
    tags=["Check task status for I-Score previous VS vuln view."],
)
async def get_iscore_vs_vuln_prev_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_iscore_vs_vuln_prev."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_vs_vuln_prev_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_iscore_pe_vuln view ---
@api_router.post(
    "/iscore_pe_vuln",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEVulnTaskResp,
    tags=["Get all PE vuln data needed for I-Score"],
)
def read_iscore_pe_vuln(
    data: schemas.VwIscorePEVulnInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_vuln_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_vuln/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEVulnTaskResp,
    tags=["Check task status for I-Score PE vuln view."],
)
async def get_iscore_pe_vuln_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_iscore_pe_vuln."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_vuln_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_iscore_pe_cred view ---
@api_router.post(
    "/iscore_pe_cred",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePECredTaskResp,
    tags=["Get all PE cred data needed for I-Score"],
)
def read_iscore_pe_cred(
    data: schemas.VwIscorePECredInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE cred data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_cred_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_cred/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePECredTaskResp,
    tags=["Check task status for I-Score PE cred view."],
)
async def get_iscore_pe_cred_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_iscore_pe_cred."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_cred_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_iscore_pe_breach view ---
@api_router.post(
    "/iscore_pe_breach",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEBreachTaskResp,
    tags=["Get all PE breach data needed for I-Score"],
)
def read_iscore_pe_breach(
    data: schemas.VwIscorePEBreachInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE breach data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_breach_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_breach/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEBreachTaskResp,
    tags=["Check task status for I-Score PE breach view."],
)
async def get_iscore_pe_breach_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_iscore_pe_breach."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_breach_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_iscore_pe_darkweb view ---
@api_router.post(
    "/iscore_pe_darkweb",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEDarkwebTaskResp,
    tags=["Get all PE darkweb data needed for I-Score"],
)
def read_iscore_pe_darkweb(
    data: schemas.VwIscorePEDarkwebInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE darkweb data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_darkweb_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_darkweb/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEDarkwebTaskResp,
    tags=["Check task status for I-Score PE darkweb view."],
)
async def get_iscore_pe_darkweb_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_iscore_pe_darkweb."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_darkweb_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_iscore_pe_protocol view ---
@api_router.post(
    "/iscore_pe_protocol",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEProtocolTaskResp,
    tags=["Get all PE protocol data needed for I-Score"],
)
def read_iscore_pe_protocol(
    data: schemas.VwIscorePEProtocolInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE protocol data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_pe_protocol_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_pe_protocol/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscorePEProtocolTaskResp,
    tags=["Check task status for I-Score PE protocol view."],
)
async def get_iscore_pe_protocol_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_iscore_pe_protocol."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_pe_protocol_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_iscore_was_vuln view ---
@api_router.post(
    "/iscore_was_vuln",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreWASVulnTaskResp,
    tags=["Get all WAS vuln data needed for I-Score"],
)
def read_iscore_was_vuln(
    data: schemas.VwIscoreWASVulnInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all WAS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_was_vuln_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_was_vuln/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreWASVulnTaskResp,
    tags=["Check task status for I-Score WAS vuln view."],
)
async def get_iscore_was_vuln_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_iscore_was_vuln."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_was_vuln_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_iscore_was_vuln_prev view ---
@api_router.post(
    "/iscore_was_vuln_prev",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreWASVulnPrevTaskResp,
    tags=["Get all previous WAS vuln data needed for I-Score"],
)
def read_iscore_was_vuln_prev(
    data: schemas.VwIscoreWASVulnPrevInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all previous WAS vuln data needed for I-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_iscore_was_vuln_prev_info.delay(
                data.specified_orgs, data.start_date, data.end_date
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/iscore_was_vuln_prev/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreWASVulnPrevTaskResp,
    tags=["Check task status for I-Score previous WAS vuln view."],
)
async def get_iscore_was_vuln_prev_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_iscore_was_vuln_prev."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_iscore_was_vuln_prev_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoint for KEV list query (no view) ---
@api_router.post(
    "/kev_list",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.KEVListTaskResp,
    tags=["Get list of all KEVs."],
)
def read_kev_list(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get list of all KEVs."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_kev_list_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/kev_list/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.KEVListTaskResp,
    tags=["Check task status for KEV list query."],
)
async def get_kev_list_task_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Get task status for kev_list."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_kev_list_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# ---------- D-Score View Endpoints, Issue 571 ----------
# --- Endpoints for vw_dscore_vs_cert view ---
@api_router.post(
    "/dscore_vs_cert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreVSCertTaskResp,
    tags=["Get all VS cert data needed for D-Score"],
)
def read_dscore_vs_cert(
    data: schemas.VwDscoreVSCertInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all VS cert data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_vs_cert_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_vs_cert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreVSCertTaskResp,
    tags=["Check task status for D-Score VS cert view."],
)
async def get_dscore_vs_cert_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get discvoery score VS cert task status."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_vs_cert_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_dscore_vs_mail view ---
@api_router.post(
    "/dscore_vs_mail",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreVSMailTaskResp,
    tags=["Get all VS mail data needed for D-Score"],
)
def read_dscore_vs_mail(
    data: schemas.VwDscoreVSMailInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all VS mail data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_vs_mail_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_vs_mail/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreVSMailTaskResp,
    tags=["Check task status for D-Score VS mail view."],
)
async def get_dscore_vs_mail_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status of read_dscore_vs_mail."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_vs_mail_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_dscore_pe_ip view ---
@api_router.post(
    "/dscore_pe_ip",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscorePEIpTaskResp,
    tags=["Get all PE IP data needed for D-Score"],
)
def read_dscore_pe_ip(
    data: schemas.VwDscorePEIpInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE IP data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_pe_ip_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_pe_ip/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscorePEIpTaskResp,
    tags=["Check task status for D-Score PE IP view."],
)
async def get_dscore_pe_ip_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status of read_dscore_pe_ip."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_pe_ip_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_dscore_pe_domain view ---
@api_router.post(
    "/dscore_pe_domain",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscorePEDomainTaskResp,
    tags=["Get all PE domain data needed for D-Score"],
)
def read_dscore_pe_domain(
    data: schemas.VwDscorePEDomainInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all PE domain data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_pe_domain_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_pe_domain/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscorePEDomainTaskResp,
    tags=["Check task status for D-Score PE domain view."],
)
async def get_dscore_pe_domain_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_dscore_pe_domain."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_pe_domain_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for vw_dscore_was_webapp view ---
@api_router.post(
    "/dscore_was_webapp",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreWASWebappTaskResp,
    tags=["Get all WAS webapp data needed for D-Score"],
)
def read_dscore_was_webapp(
    data: schemas.VwDscoreWASWebappInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all WAS webapp data needed for D-Score."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_dscore_was_webapp_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/dscore_was_webapp/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwDscoreWASWebappTaskResp,
    tags=["Check task status for D-Score WAS webapp view."],
)
async def get_dscore_was_webapp_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_dscore_was_webapp."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_dscore_was_webapp_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for FCEB status query (no view) ---
@api_router.post(
    "/fceb_status",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.FCEBStatusTaskResp,
    tags=["Get the FCEB status of a specified list of organizations."],
)
def read_fceb_status(
    data: schemas.FCEBStatusInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the FCEB status of a specified list of organizations."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_fceb_status_info.delay(data.specified_orgs)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/fceb_status/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.FCEBStatusTaskResp,
    tags=["Check task status for FCEB status query."],
)
async def get_fceb_status_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for fceb_status."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_fceb_status_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# ---------- Misc. Score Endpoints ----------
# --- Endpoints for XS stakeholder list query ---
@api_router.post(
    "/xs_stakeholders",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all XS stakeholders."],
)
def read_xs_stakeholders(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get list of all XS stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_xs_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/xs_stakeholders/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for XS stakeholder query."],
)
async def get_xs_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_xs_stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_xs_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for S stakeholder list query ---
@api_router.post(
    "/s_stakeholders",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all S stakeholders."],
)
def read_s_stakeholders(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get list of all S stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_s_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/s_stakeholders/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for S stakeholder query."],
)
async def get_s_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_s_stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_s_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for M stakeholder list query ---
@api_router.post(
    "/m_stakeholders",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all M stakeholders."],
)
def read_m_stakeholders(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get list of all M stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_m_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/m_stakeholders/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for M stakeholder query."],
)
async def get_m_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_m_stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_m_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for L stakeholder list query ---
@api_router.post(
    "/l_stakeholders",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all L stakeholders."],
)
def read_l_stakeholders(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get list of all L stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_l_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/l_stakeholders/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for L stakeholder query."],
)
async def get_l_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_l_stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_l_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Endpoints for XL stakeholder list query ---
@api_router.post(
    "/xl_stakeholders",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Get list of all XL stakeholders."],
)
def read_xl_stakeholders(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get list of all XL stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_xl_stakeholders_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/xl_stakeholders/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.VwIscoreOrgsIpCountsTaskResp,
    tags=["Check task status for XL stakeholder query."],
)
async def get_xl_stakeholders_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for read_xl_stakeholders."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_xl_stakeholders_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# ---------- Misc. Endpoints ----------


@api_router.post(
    "/data_source/{source_name}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    # response_model=schemas.DataSource,
    tags=["Get Data_source table"],
)
def get_data_source(source_name: str, tokens: dict = Depends(get_api_key)):
    """Get data source API endpoint."""
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            try:
                datas = list(DataSource.objects.filter(name=f"{source_name}"))
                print(datas)
                return datas[0]
            except ValidationError:
                return {"message": "Data source does not exist"}

        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# data_source_uid: str,request: Request, tokens: dict = Depends(get_api_key)


@api_router.put(
    "/update_last_viewed/{data_source_uid}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    tags=["Update last viewed data"],
)
@transaction.atomic
def update_last_viewed(data_source_uid: str, tokens: dict = Depends(get_api_key)):
    """Update last viewed column in the datasource table."""
    if not tokens:
        return {"message": "No api key was submitted"}
    LOGGER.info(f"The api key submitted {tokens}")
    try:
        userapiTokenverify(theapiKey=tokens)
        try:
            data_source = DataSource.objects.get(data_source_uid=data_source_uid)
        except ValidationError:
            return {"message": "Data source does not exist"}
        data_source.last_run = datetime.today().strftime("%Y-%m-%d")
        data_source.save()
        return {"message": "Record updated successfully."}
    except ObjectDoesNotExist:
        LOGGER.info("API key expired please try again")


# --- execute_ips(), Issue 559 ---
@api_router.post(
    "/ips_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsInsertTaskResp,
    tags=["Insert new ip records into the ips table"],
)
def ips_insert(data: schemas.IpsInsertInput, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to insert new ip records into the ips table."""
    # Convert list of input models to list of dictionaries
    new_ips = [dict(input_dict) for input_dict in data.new_ips]
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = ips_insert_task.delay(new_ips)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/ips_insert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsInsertTaskResp,
    tags=["Check task status for ips_insert endpoint task."],
)
async def ips_insert_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of ips_insert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = ips_insert_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_all_subs(), Issue 560 ---
@api_router.post(
    "/sub_domains_table",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.SubDomainPagedTaskResp,
    tags=["Get all data from the sub_domains table"],
)
def sub_domains_table(
    data: schemas.SubDomainPagedInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get all data from the sub_domains table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = sub_domains_table_task.delay(data.page, data.per_page)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/sub_domains_table/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.SubDomainPagedTaskResp,
    tags=["Check task status for sub_domains_table endpoint task."],
)
async def sub_domains_table_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of sub_domains_table task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = sub_domains_table_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_domMasq_alerts(), Issue 562 ---
@api_router.post(
    "/domain_alerts_by_org_date",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.DomainAlertsTable],
    tags=["Get all domain_alerts table data for the specified org_uid and date range."],
)
def domain_alerts_by_org_date(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all domain_alerts table data for the specified org_uid and date range."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            domain_alerts_by_org_date_data = list(
                DomainAlerts.objects.filter(
                    organizations_uid=data.org_uid,
                    date__range=[data.start_date, data.end_date],
                ).values()
            )
            # Convert uuids to strings
            for row in domain_alerts_by_org_date_data:
                row["domain_alert_uid"] = convert_uuid_to_string(
                    row["domain_alert_uid"]
                )
                row["sub_domain_uid_id"] = convert_uuid_to_string(
                    row["sub_domain_uid_id"]
                )
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
                row["date"] = convert_date_to_string(row["date"])
            # Catch query no results scenario
            if not domain_alerts_by_org_date_data:
                domain_alerts_by_org_date_data = [
                    {x: None for x in schemas.DomainAlertsTable.__fields__}
                ]
            return domain_alerts_by_org_date_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_domMasq(), Issue 563 ---
@api_router.post(
    "/domain_permu_by_org_date",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.DomainPermuTable],
    tags=[
        "Get all domain_permutations table data for the specified org_uid and date range."
    ],
)
def domain_permu_by_org_date(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all domain_permutations table data for the specified org_uid and date range."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            domain_permu_by_org_date_data = list(
                DomainPermutations.objects.filter(
                    organizations_uid=data.org_uid,
                    date_active__range=[data.start_date, data.end_date],
                ).values()
            )
            # Convert uuids to strings
            for row in domain_permu_by_org_date_data:
                row["suspected_domain_uid"] = convert_uuid_to_string(
                    row["suspected_domain_uid"]
                )
                row["organizations_uid_id"] = convert_uuid_to_string(
                    row["organizations_uid_id"]
                )
                row["date_observed"] = convert_date_to_string(row["date_observed"])
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
                row["sub_domain_uid_id"] = convert_uuid_to_string(
                    row["sub_domain_uid_id"]
                )
                row["date_active"] = convert_date_to_string(row["date_active"])
            # Catch query no results scenario
            if not domain_permu_by_org_date_data:
                domain_permu_by_org_date_data = [
                    {x: None for x in schemas.DomainPermuTable.__fields__}
                ]
            return domain_permu_by_org_date_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_roots(), Issue 564 ---
@api_router.post(
    "/root_domains_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert list of root domains for the specified org."],
)
def root_domains_insert(
    data: schemas.RootDomainsInsertInput, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to insert list of root domains for the specified org."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            org_dict = data.org_dict.__dict__
            # If API key valid, go through and insert domains
            insert_count = 0
            for domain in data.domain_list:
                # Check if record already exists
                domain_results = RootDomains.objects.filter(
                    root_domain=domain,
                    organizations_uid=org_dict["organizations_uid"],
                )
                if not domain_results.exists():
                    # If not, insert new record
                    curr_org_uid = Organizations.objects.get(
                        organizations_uid=org_dict["organizations_uid"]
                    )
                    try:
                        ip = socket.gethostbyname(domain)
                    except Exception:
                        ip = None
                    pe_data_source_uid = DataSource.objects.get(name="P&E")
                    RootDomains.objects.create(
                        root_domain_uid=uuid.uuid1(),
                        organizations_uid=curr_org_uid,
                        root_domain=domain,
                        ip_address=ip,
                        data_source_uid=pe_data_source_uid,
                        enumerate_subs=True,
                    )
                    insert_count += 1
            return (
                str(insert_count)
                + " domains were inserted into root_domains table for "
                + org_dict["cyhy_db_name"]
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_orgs_contacts(), Issue 601 ---
@api_router.get(
    "/orgs_report_on_contacts",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrgsReportOnContacts],
    tags=["Get all contact data for orgs where report_on is true."],
)
def orgs_report_on_contacts(tokens: dict = Depends(get_api_key)):
    """Create API endpoint to get all contact data for orgs where report_on is true."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            orgs_report_on_contacts_data = list(
                CyhyContacts.objects.filter(
                    org_id__in=Organizations.objects.filter(report_on=True).values(
                        "cyhy_db_name"
                    )
                ).values("email", "contact_type", "org_id")
            )
            return orgs_report_on_contacts_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_org_assets_count_past(), Issue 603 ---
@api_router.post(
    "/past_asset_counts_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.RSSTable],
    tags=["Get all RSS data for the specified org_uid and date."],
)
def past_asset_counts_by_org(
    data: schemas.GenInputOrgUIDDateSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all RSS data for the specified org_uid and date."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            past_asset_counts_by_org_data = list(
                ReportSummaryStats.objects.filter(
                    organizations_uid=data.org_uid, end_date=data.date
                ).values()
            )
            # Convert uuids to strings
            for row in past_asset_counts_by_org_data:
                row["report_uid"] = convert_uuid_to_string(row["report_uid"])
                row["organizations_uid_id"] = convert_uuid_to_string(
                    row["organizations_uid_id"]
                )
                row["start_date"] = convert_date_to_string(row["start_date"])
                row["end_date"] = convert_date_to_string(row["end_date"])
            # Catch query no results scenario
            if not past_asset_counts_by_org_data:
                past_asset_counts_by_org_data = [
                    {x: None for x in schemas.RSSTable.__fields__}
                ]
            return past_asset_counts_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_org_assets_count(), Issue 604 ---
@api_router.post(
    "/asset_counts_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.AssetCountsByOrg],
    tags=["Get attacksurface data for the specified org_uid."],
)
def asset_counts_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get attacksurface data for the specified org_uid."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            asset_counts_by_org_data = list(
                VwOrgsAttacksurface.objects.filter(
                    organizations_uid=data.org_uid
                ).values(
                    "organizations_uid",
                    "cyhy_db_name",
                    "num_root_domain",
                    "num_sub_domain",
                    "num_ips",
                    "num_ports",
                    "num_cidrs",
                    "num_ports_protocols",
                    "num_software",
                    "num_foreign_ips",
                )
            )
            # Convert uuids to strings
            for row in asset_counts_by_org_data:
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
            return asset_counts_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_new_orgs(), Issue 605 ---
@api_router.get(
    "/orgs_report_on_false",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrgsTable],
    tags=["Get all data for organizations where report on is false."],
)
def orgs_report_on_false(tokens: dict = Depends(get_api_key)):
    """Create API endpoint to get all data for organizations where report on is false."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            orgs_report_on_false_data = list(
                Organizations.objects.filter(report_on=False).values()
            )
            # Convert uuids to strings
            for row in orgs_report_on_false_data:
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
                row["org_type_uid_id"] = convert_uuid_to_string(row["org_type_uid_id"])
                row["date_first_reported"] = convert_date_to_string(
                    row["date_first_reported"]
                )
                row["parent_org_uid_id"] = convert_uuid_to_string(
                    row["parent_org_uid_id"]
                )
                row["cyhy_period_start"] = convert_date_to_string(
                    row["cyhy_period_start"]
                )
            return orgs_report_on_false_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- set_org_to_report_on(), Issue 606 ---
@api_router.post(
    "/orgs_set_report_on",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrgsTable],
    tags=["Set report_on to true for the specified organization."],
)
def orgs_set_report_on(
    data: schemas.OrgsSetReportOnInput, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to set report_on to true for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            specified_org = list(
                Organizations.objects.filter(cyhy_db_name=data.cyhy_db_name).values()
            )
            if len(specified_org) != 0:
                # If org exists, update fields
                Organizations.objects.filter(cyhy_db_name=data.cyhy_db_name).update(
                    report_on=True, premium_report=data.premium, demo=False
                )
                # Convert uuids to strings
                for row in specified_org:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["org_type_uid_id"] = convert_uuid_to_string(
                        row["org_type_uid_id"]
                    )
                    row["date_first_reported"] = convert_date_to_string(
                        row["date_first_reported"]
                    )
                    row["parent_org_uid_id"] = convert_uuid_to_string(
                        row["parent_org_uid_id"]
                    )
                    row["cyhy_period_start"] = convert_date_to_string(
                        row["cyhy_period_start"]
                    )
                return specified_org
            else:
                # Otherwise, return empty
                LOGGER.error("No org found for that cyhy id")
                return [
                    {
                        "organizations_uid": "NOT FOUND",
                        "name": "",
                        "cyhy_db_name": "",
                        "org_type_uid_id": "",
                        "report_on": False,
                        "password": "",
                        "date_first_reported": "",
                        "parent_org_uid_id": "",
                        "premium_report": False,
                        "agency_type": "",
                        "demo": False,
                        "scorecard": False,
                        "fceb": False,
                        "receives_cyhy_report": False,
                        "receives_bod_report": False,
                        "receives_cybex_report": False,
                        "run_scans": False,
                        "is_parent": False,
                        "ignore_roll_up": True,
                        "retired": True,
                        "cyhy_period_start": "",
                        "fceb_child": False,
                        "election": False,
                        "scorecard_child": False,
                    }
                ]
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- set_org_to_demo(), Issue 607 ---
@api_router.post(
    "/orgs_set_demo",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrgsTable],
    tags=["Set demo to true for the specified organization."],
)
def orgs_set_demo(
    data: schemas.OrgsSetReportOnInput, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to set demo to true for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            specified_org = list(
                Organizations.objects.filter(cyhy_db_name=data.cyhy_db_name).values()
            )
            LOGGER.info(specified_org)
            if len(specified_org) != 0:
                # If org exists, update fields
                Organizations.objects.filter(cyhy_db_name=data.cyhy_db_name).update(
                    report_on=False, premium_report=data.premium, demo=True
                )
                # Convert uuids to strings
                for row in specified_org:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["org_type_uid_id"] = convert_uuid_to_string(
                        row["org_type_uid_id"]
                    )
                    row["date_first_reported"] = convert_date_to_string(
                        row["date_first_reported"]
                    )
                    row["parent_org_uid_id"] = convert_uuid_to_string(
                        row["parent_org_uid_id"]
                    )
                    row["cyhy_period_start"] = convert_date_to_string(
                        row["cyhy_period_start"]
                    )
                return specified_org
            else:
                # Otherwise, return empty
                LOGGER.error("No org found for that cyhy id")
                return [
                    {
                        "organizations_uid": "NOT FOUND",
                        "name": "",
                        "cyhy_db_name": "",
                        "org_type_uid_id": "",
                        "report_on": False,
                        "password": "",
                        "date_first_reported": "",
                        "parent_org_uid_id": "",
                        "premium_report": False,
                        "agency_type": "",
                        "demo": False,
                        "scorecard": False,
                        "fceb": False,
                        "receives_cyhy_report": False,
                        "receives_bod_report": False,
                        "receives_cybex_report": False,
                        "run_scans": False,
                        "is_parent": False,
                        "ignore_roll_up": True,
                        "retired": True,
                        "cyhy_period_start": "",
                        "fceb_child": False,
                        "election": False,
                        "scorecard_child": False,
                    }
                ]
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_cyhy_assets(), Issue 608 ---
@api_router.post(
    "/cyhy_assets_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.CyhyDbAssetsByOrg],
    tags=["Get all cyhy assets for the specified organization."],
)
def cyhy_assets_by_org(
    data: schemas.GenInputOrgCyhyNameSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all cyhy assets for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            cyhy_assets_by_org_data = list(
                CyhyDbAssets.objects.filter(
                    org_id=data.org_cyhy_name, currently_in_cyhy=True
                ).values()
            )
            # Convert uuids to strings
            for row in cyhy_assets_by_org_data:
                row["field_id"] = convert_uuid_to_string(row["field_id"])
                row["first_seen"] = convert_date_to_string(row["first_seen"])
                row["last_seen"] = convert_date_to_string(row["last_seen"])
            # Catch query no results scenario
            if not cyhy_assets_by_org_data:
                cyhy_assets_by_org_data = [
                    {x: None for x in schemas.CyhyDbAssetsByOrg.__fields__}
                ]
            return cyhy_assets_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_cidrs_and_ips(), Issue 610 ---
@api_router.post(
    "/cidrs_ips_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.CidrsIpsByOrg],
    tags=["Get all CIDRs and IPs for the specified organization."],
)
def cidrs_ips_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all CIDRs and IPs for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            cidr_ip_data = list(
                Cidrs.objects.filter(organizations_uid=data.org_uid).values(
                    ip=F("network")
                )
            )
            sub_root_ip_data = list(
                VwIpsSubRootOrgInfo.objects.filter(
                    organizations_uid=data.org_uid,
                    origin_cidr__isnull=True,
                    i_current=True,
                    sd_current=True,
                ).values("ip")
            )
            cidrs_ips_by_org_data = cidr_ip_data + sub_root_ip_data
            return cidrs_ips_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_ips(), Issue 611 ---
@api_router.post(
    "/ips_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsByOrg,
    tags=["Get all IPs for the specified organization."],
)
def ips_by_org(data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)):
    """Create API endpoint to get all IPs for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            cidr_ip_data = list(
                VwIpsCidrOrgInfo.objects.filter(
                    organizations_uid=data.org_uid, origin_cidr__isnull=False
                ).values("ip")
            )
            sub_root_ip_data = list(
                VwIpsSubRootOrgInfo.objects.filter(
                    organizations_uid=data.org_uid
                ).values("ip")
            )
            return {"cidr_ip_data": cidr_ip_data, "sub_root_ip_data": sub_root_ip_data}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_extra_ips(), Issue 612 ---
@api_router.post(
    "/extra_ips_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.ExtraIpsByOrg],
    tags=["Get all extra IPs for the specified organization."],
)
def extra_ips_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all extra IPs for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            extra_ips_by_org_data = list(
                VwIpsSubRootOrgInfo.objects.filter(
                    organizations_uid=data.org_uid,
                    origin_cidr__isnull=True,
                    i_current=True,
                    sd_current=True,
                ).values("ip_hash", "ip")
            )
            return extra_ips_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- set_from_cidr(), Issue 616 ---
@api_router.post(
    "/ips_update_from_cidr",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsUpdateFromCidrTaskResp,
    tags=["Set from_cidr to True for any IPs that have an origin CIDR."],
)
def ips_update_from_cidr(tokens: dict = Depends(get_api_key)):
    """Create API endpoint to set from_cidr to True for any IPs that have an origin CIDR."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = ips_update_from_cidr_task.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/ips_update_from_cidr/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.IpsUpdateFromCidrTaskResp,
    tags=["Check task status for ips_update_from_cidr endpoint task."],
)
async def ips_update_from_cidr_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to check status of ips_update_from_cidr endpoint task."""
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = ips_update_from_cidr_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_cidrs_by_org(), Issue 618 ---
@api_router.post(
    "/cidrs_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.CidrsByOrg],
    tags=["Get all CIDRs for a specified organization."],
)
def cidrs_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all CIDRs for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            cidrs_by_org_data = list(
                Cidrs.objects.filter(
                    organizations_uid=data.org_uid, current=True
                ).values()
            )
            # Convert uuids to strings
            for row in cidrs_by_org_data:
                row["cidr_uid"] = convert_uuid_to_string(row["cidr_uid"])
                row["organizations_uid_id"] = convert_uuid_to_string(
                    row["organizations_uid_id"]
                )
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
                row["first_seen"] = convert_date_to_string(row["first_seen"])
                row["last_seen"] = convert_date_to_string(row["last_seen"])
            # Catch query no results scenario
            if not cidrs_by_org_data:
                cidrs_by_org_data = [{x: None for x in schemas.CidrsByOrg.__fields__}]
            return cidrs_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_ports_protocols(), Issue 619 ---
@api_router.post(
    "/ports_protocols_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.PortsProtocolsByOrg],
    tags=["Get all distinct ports/protocols for a specified organization."],
)
def ports_protocols_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all distinct ports/protocols for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            ports_protocols_by_org_data = list(
                ShodanAssets.objects.filter(organizations_uid=data.org_uid)
                .values("port", "protocol")
                .distinct()
            )
            # Catch query no results scenario
            if not ports_protocols_by_org_data:
                ports_protocols_by_org_data = [
                    {x: None for x in schemas.PortsProtocolsByOrg.__fields__}
                ]
            return ports_protocols_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_software(), Issue 620 ---
@api_router.post(
    "/software_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.SoftwareByOrg],
    tags=["Get all distinct software products for a specified organization."],
)
def software_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all distinct software products for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            software_by_org_data = list(
                ShodanAssets.objects.filter(
                    organizations_uid=data.org_uid, product__isnull=False
                )
                .values("product")
                .distinct()
            )
            # Catch query no results scenario
            if not software_by_org_data:
                software_by_org_data = [
                    {x: None for x in schemas.SoftwareByOrg.__fields__}
                ]
            return software_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_foreign_IPs(), Issue 621 ---
@api_router.post(
    "/foreign_ips_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.ForeignIpsByOrg],
    tags=["Get all foreign IPs for a specified organization."],
)
def foreign_ips_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all foreign IPs for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            foreign_ips_by_org_data = list(
                ShodanAssets.objects.filter(
                    organizations_uid=data.org_uid, country_code__isnull=False
                )
                .exclude(country_code="US")
                .values()
            )
            # Convert uuids to strings
            for row in foreign_ips_by_org_data:
                row["shodan_asset_uid"] = convert_uuid_to_string(
                    row["shodan_asset_uid"]
                )
                row["organizations_uid_id"] = convert_uuid_to_string(
                    row["organizations_uid_id"]
                )
                row["timestamp"] = convert_date_to_string(row["timestamp"])
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
            # Catch query no results scenario
            if not foreign_ips_by_org_data:
                foreign_ips_by_org_data = [
                    {x: None for x in schemas.ForeignIpsByOrg.__fields__}
                ]
            return foreign_ips_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_roots(), Issue 622 ---
@api_router.post(
    "/root_domains_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.RootDomainsByOrg],
    tags=["Get all root domains for a specified organization."],
)
def root_domains_by_org(
    data: schemas.GenInputOrgUIDSingle, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all root domains for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            root_domains_by_org_data = list(
                RootDomains.objects.filter(
                    organizations_uid=data.org_uid, enumerate_subs=True
                ).values("root_domain_uid", "root_domain")
            )
            # Convert uuids to strings
            for row in root_domains_by_org_data:
                row["root_domain_uid"] = convert_uuid_to_string(row["root_domain_uid"])
            # Catch query no results scenario
            if not root_domains_by_org_data:
                root_domains_by_org_data = [
                    {x: None for x in schemas.RootDomainsByOrg.__fields__}
                ]
            return root_domains_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_creds_view(), Issue 623 ---
@api_router.post(
    "/breachcomp_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.VwBreachcomp],
    tags=["Get vw_breachcomp data for specified org and date range."],
)
def breachcomp_by_org(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get vw_breachcomp data for specified org and date range."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            breachcomp_by_org_data = list(
                VwBreachcomp.objects.filter(
                    organizations_uid=data.org_uid,
                    modified_date__date__range=(data.start_date, data.end_date),
                ).values()
            )
            # Convert uuids to strings
            for row in breachcomp_by_org_data:
                row["credential_exposures_uid"] = convert_uuid_to_string(
                    row["credential_exposures_uid"]
                )
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
                row["data_source_uid"] = convert_uuid_to_string(row["data_source_uid"])
                row["breach_date"] = convert_date_to_string(row["breach_date"])
                row["added_date"] = convert_date_to_string(row["added_date"])
                row["modified_date"] = convert_date_to_string(row["modified_date"])
            # Catch query no results scenario
            if not breachcomp_by_org_data:
                breachcomp_by_org_data = [
                    {x: None for x in schemas.VwBreachcomp.__fields__}
                ]
            return breachcomp_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_credsbyday_view(), Issue 624 ---
@api_router.post(
    "/credsbydate_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.CredsbydateByOrg],
    tags=["Get vw_breachcomp_credsbydate data for specified org and date range."],
)
def credsbydate_by_org(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get vw_breachcomp_credsbydate data for specified org and date range."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            credsbydate_by_org_data = list(
                VwBreachcompCredsbydate.objects.filter(
                    organizations_uid=data.org_uid,
                    mod_date__range=(data.start_date, data.end_date),
                ).values("mod_date", "no_password", "password_included")
            )
            # Convert uuids to strings
            for row in credsbydate_by_org_data:
                row["mod_date"] = convert_date_to_string(row["mod_date"])
            # Catch query no results scenario
            if not credsbydate_by_org_data:
                credsbydate_by_org_data = [
                    {x: None for x in schemas.CredsbydateByOrg.__fields__}
                ]
            return credsbydate_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_breachdetails_view(), Issue 625 ---
@api_router.post(
    "/breachdetails_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.BreachdetailsByOrg],
    tags=["Get vw_breachcomp_breachdetails data for specified org and date range."],
)
def breachdetails_by_org(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get vw_breachcomp_breachdetails data for specified org and date range."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            breachdetails_by_org_data = list(
                VwBreachcompBreachdetails.objects.filter(
                    organizations_uid=data.org_uid,
                    mod_date__range=(data.start_date, data.end_date),
                ).values(
                    "breach_name",
                    "mod_date",
                    "breach_date",
                    "password_included",
                    "number_of_creds",
                )
            )
            # Convert uuids to strings
            for row in breachdetails_by_org_data:
                row["mod_date"] = convert_date_to_string(row["mod_date"])
                row["breach_date"] = convert_date_to_string(row["breach_date"])
            # Catch query no results scenario
            if not breachdetails_by_org_data:
                breachdetails_by_org_data = [
                    {x: None for x in schemas.BreachdetailsByOrg.__fields__}
                ]
            return breachdetails_by_org_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Issue 626 ---
# Query domain masquerading on the domain permutattions tables
@api_router.post(
    "/dom_masq",
    # response_model=schemas.DarkWebCvesTaskResp,
    tags=["query the domain masq data."],
)
def dom_masq(data: schemas.AlertInput, tokens: dict = Depends(get_api_key)):
    """Query the domain masq data."""
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            date_format = "%Y-%m-%d"
            try:
                sdate = datetime.strptime(data.start_date, date_format)
                edate = datetime.strptime(data.end_date, date_format)
            except Exception:
                return {"message": "date is in wrong format"}
            mentions = list(
                DomainPermutations.objects.filter(
                    organizations_uid=data.org_uid, date_active__range=(sdate, edate)
                ).values()
            )
            return mentions
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- Issue 627 ---
# Query domain masquerading alerts tables
@api_router.post(
    "/dom_masq_alerts",
    # response_model=schemas.DarkWebCvesTaskResp,
    tags=["query the domain masq alert data."],
)
def dom_masq_alerts(data: schemas.AlertInput, tokens: dict = Depends(get_api_key)):
    """Query the domain masq data."""
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            date_format = "%Y-%m-%d"
            try:
                sdate = datetime.strptime(data.start_date, date_format)
                edate = datetime.strptime(data.end_date, date_format)
            except Exception:
                return {"message": "date is in wrong format"}
            mentions = list(
                DomainAlerts.objects.filter(
                    organizations_uid=data.org_uid, date__range=(sdate, edate)
                ).values()
            )
            return mentions
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_shodan(), Issue 628 ---
# GenInputOrgUIDListDateRange
# vw_shodanvulns_suspected
@api_router.post(
    "/shodanvulns_suspected_view",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.VwShodanvulnsSuspectedSchema],
    tags=["Get all records for view shodanvulns_suspected_view"],
)
def shodanvulns_suspected_view(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint for shodanvulns_suspected_view."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:  # if 1:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            shodanvulns_suspected_data = list(
                VwShodanvulnsSuspected.objects.filter(
                    organizations_uid=data.org_uid,
                    timestamp__range=[data.start_date, data.end_date],
                ).values()
            )
            # Convert uuids to strings
            for row in shodanvulns_suspected_data:
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
                row["timestamp"] = convert_date_to_string(row["timestamp"])
            # Catch query no results scenario
            if not shodanvulns_suspected_data:
                shodanvulns_suspected_data = [
                    {x: None for x in schemas.VwShodanvulnsSuspectedSchema.__fields__}
                ]
            return shodanvulns_suspected_data
            # return {"Type": org_data[0]}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_shodan(), Issue 628 ---
# vw_shodanvulns_verified
@api_router.post(
    "/shodanvulns_verified_view",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.VwShodanvulnsVerifiedSchema],
    tags=["Get all records for view shodanvulns_verified_view"],
)
def shodanvulns_verified_view(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint for shodanvulns_verified_view."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:  # if 1:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            shodanvulns_verified_data = list(
                VwShodanvulnsVerified.objects.filter(
                    organizations_uid=data.org_uid,
                    timestamp__range=[data.start_date, data.end_date],
                ).values()
            )
            # Convert uuids to strings
            for row in shodanvulns_verified_data:
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
                row["timestamp"] = convert_date_to_string(row["timestamp"])
            # Catch query no results scenario
            if not shodanvulns_verified_data:
                shodanvulns_verified_data = [
                    {x: None for x in schemas.VwShodanvulnsVerifiedSchema.__fields__}
                ]
            return shodanvulns_verified_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_shodan(), Issue 628 ---
# shodan_assets
@api_router.post(
    "/shodan_assets",
    dependencies=[Depends(get_api_key)],
    response_model=List[schemas.ShodanAssetsSchema],
    tags=["Get all records for view shodan_assets"],
)
def shodan_assets(
    data: schemas.GenInputOrgUIDDateRange, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint for shodan_assets."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:  # if 1:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            shodan_assets_data = list(
                ShodanAssets.objects.filter(
                    organizations_uid=data.org_uid,
                    timestamp__range=[data.start_date, data.end_date],
                ).values()
            )
            # Convert uuids to strings
            for row in shodan_assets_data:
                row["shodan_asset_uid"] = convert_uuid_to_string(
                    row["shodan_asset_uid"]
                )
                row["organizations_uid_id"] = convert_uuid_to_string(
                    row["organizations_uid_id"]
                )
                row["timestamp"] = convert_date_to_string(row["timestamp"])
                row["data_source_uid_id"] = convert_uuid_to_string(
                    row["data_source_uid_id"]
                )
            # Catch query no results scenario
            if not shodan_assets_data:
                shodan_assets_data = [
                    {x: None for x in schemas.ShodanAssetsSchema.__fields__}
                ]
            return shodan_assets_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_darkweb(), Issue 629 ---
@api_router.post(
    "/darkweb_data",
    # response_model=Union[
    #     #schemas.MentionsTable,
    #     List[schemas.AlertsTable],
    #     List[schemas.VwDarkwebMentionsbydate],
    #     #schemas.VwDarkwebInviteonlymarkets,
    #     #schemas.VwDarkwebSocmediaMostactposts,
    #     #List[schemas.VwDarkwebMostactposts],
    #     #schemas.VwDarkwebExecalerts,
    #     #schemas.VwDarkwebAssetalerts,
    #     #schemas.VwDarkwebThreatactors,
    #     #schemas.VwDarkwebPotentialthreats,
    #     #schemas.VwDarkwebSites,
    # ],
    tags=["Get darkweb data from various tables"],
)
def darkweb_data(data: schemas.DarkWebDataInput, tokens: dict = Depends(get_api_key)):
    """Create API Endpoint to query the darkweb data from various tables."""
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            sdate = data.start_date
            edate = data.end_date
            if data.table == "mentions":
                mentions = list(
                    Mentions.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )[:10]
                # Make fields serializable
                for row in mentions:
                    row["mentions_uid"] = convert_uuid_to_string(row["mentions_uid"])
                    row["date"] = convert_date_to_string(row["date"])
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["data_source_uid_id"] = convert_uuid_to_string(
                        row["data_source_uid_id"]
                    )
                if not mentions:
                    mentions = [{x: None for x in schemas.MentionsTable.__fields__}]
                return mentions
            elif data.table == "alerts":
                alerts = list(
                    Alerts.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in alerts:
                    row["organizations_uid_id"] = convert_uuid_to_string(
                        row["organizations_uid_id"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                    row["alerts_uid"] = convert_uuid_to_string(row["alerts_uid"])
                    row["data_source_uid_id"] = convert_uuid_to_string(
                        row["data_source_uid_id"]
                    )
                if not alerts:
                    alerts = [{x: None for x in schemas.AlertsTable.__fields__}]
                return alerts
            elif data.table == "vw_darkweb_mentionsbydate":
                mentionsbydate = list(
                    VwDarkwebMentionsbydate.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in mentionsbydate:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                if not mentionsbydate:
                    mentionsbydate = [
                        {x: None for x in schemas.VwDarkwebMentionsbydate.__fields__}
                    ]
                return mentionsbydate
            elif data.table == "vw_darkweb_inviteonlymarkets":
                inviteonlymarkets = list(
                    VwDarkwebInviteonlymarkets.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in inviteonlymarkets:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                if not inviteonlymarkets:
                    inviteonlymarkets = [
                        {x: None for x in schemas.VwDarkwebInviteonlymarkets.__fields__}
                    ]
                return inviteonlymarkets
            elif data.table == "vw_darkweb_socmedia_mostactposts":
                socmedia_mostactposts = list(
                    VwDarkwebSocmediaMostactposts.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in socmedia_mostactposts:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                if not socmedia_mostactposts:
                    socmedia_mostactposts = [
                        {
                            x: None
                            for x in schemas.VwDarkwebSocmediaMostactposts.__fields__
                        }
                    ]
                return socmedia_mostactposts
            elif data.table == "vw_darkweb_mostactposts":
                mostactposts = list(
                    VwDarkwebMostactposts.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in mostactposts:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                if not mostactposts:
                    mostactposts = [
                        {x: None for x in schemas.VwDarkwebMostactposts.__fields__}
                    ]
                return mostactposts
            elif data.table == "vw_darkweb_execalerts":
                execalerts = list(
                    VwDarkwebExecalerts.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in execalerts:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                if not execalerts:
                    execalerts = [
                        {x: None for x in schemas.VwDarkwebExecalerts.__fields__}
                    ]
                return execalerts
            elif data.table == "vw_darkweb_assetalerts":
                assetalerts = list(
                    VwDarkwebAssetalerts.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in assetalerts:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                if not assetalerts:
                    assetalerts = [
                        {x: None for x in schemas.VwDarkwebAssetalerts.__fields__}
                    ]
                return assetalerts
            elif data.table == "vw_darkweb_threatactors":
                threatactors = list(
                    VwDarkwebThreatactors.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in threatactors:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                if not threatactors:
                    threatactors = [
                        {x: None for x in schemas.VwDarkwebThreatactors.__fields__}
                    ]
                return threatactors
            elif data.table == "vw_darkweb_potentialthreats":
                potentialthreats = list(
                    VwDarkwebPotentialthreats.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in potentialthreats:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                if not potentialthreats:
                    potentialthreats = [
                        {x: None for x in schemas.VwDarkwebPotentialthreats.__fields__}
                    ]
                return potentialthreats
            elif data.table == "vw_darkweb_sites":
                sites = list(
                    VwDarkwebSites.objects.filter(
                        organizations_uid=data.org_uid, date__range=(sdate, edate)
                    ).values()
                )
                # Make fields serializable
                for row in sites:
                    row["organizations_uid"] = convert_uuid_to_string(
                        row["organizations_uid"]
                    )
                    row["date"] = convert_date_to_string(row["date"])
                if not sites:
                    sites = [{x: None for x in schemas.VwDarkwebSites.__fields__}]
                return sites
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_darkweb_cves(), Issue 630 ---
@api_router.post(
    "/darkweb_cves",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.DarkWebCvesTaskResp,
    tags=["Get all darkweb cve data"],
)
def darkweb_cves(tokens: dict = Depends(get_api_key)):
    """Create API endpoint to get all darkweb cve data."""
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = darkweb_cves_task.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/darkweb_cves/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.DarkWebCvesTaskResp,
    tags=["Check task status for darkweb_cves endpoint task."],
)
async def darkweb_cves_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Create API endpoint to check status of darkweb_cves endpoint task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = darkweb_cves_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- execute_scorecard(), Issue 632 ---
@api_router.put(
    "/rss_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    # response_model=None (nothing returned)
    tags=["Insert an organization's record into the report_summary_stats table"],
)
def rss_insert(data: schemas.RSSInsertInput, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to insert an organization's record into the report_summary_stats table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid
            # Get Organizations.organization_uid object for the specified org
            specified_org_uid = Organizations.objects.get(
                organizations_uid=data.organizations_uid
            )
            try:
                # Check if record already exists
                ReportSummaryStats.objects.get(
                    organizations_uid=specified_org_uid,
                    start_date=data.start_date
                )
                # If it already exists, update
                ReportSummaryStats.objects.filter(
                    organizations_uid=specified_org_uid,
                    start_date=data.start_date,
                ).update(
                    ip_count=data.ip_count,
                    root_count=data.root_count,
                    sub_count=data.sub_count,
                    ports_count=data.num_ports,
                    creds_count=data.creds_count,
                    breach_count=data.breach_count,
                    cred_password_count=data.cred_password_count,
                    domain_alert_count=data.domain_alert_count,
                    suspected_domain_count=data.suspected_domain_count,
                    insecure_port_count=data.insecure_port_count,
                    verified_vuln_count=data.verified_vuln_count,
                    suspected_vuln_count=data.suspected_vuln_count,
                    suspected_vuln_addrs_count=data.suspected_vuln_addrs_count,
                    threat_actor_count=data.threat_actor_count,
                    dark_web_alerts_count=data.dark_web_alerts_count,
                    dark_web_mentions_count=data.dark_web_mentions_count,
                    dark_web_executive_alerts_count=data.dark_web_executive_alerts_count,
                    dark_web_asset_alerts_count=data.dark_web_asset_alerts_count,
                    pe_number_score=data.pe_number_score,
                    pe_letter_grade=data.pe_letter_grade,
                    cidr_count=data.cidr_count,
                    port_protocol_count=data.port_protocol_count,
                    software_count=data.software_count,
                    foreign_ips_count=data.foreign_ips_count,
                )
            except ReportSummaryStats.DoesNotExist:
                # Otherwise, create a new record
                ReportSummaryStats.objects.create(
                    report_uid=uuid.uuid1(),
                    organizations_uid=specified_org_uid,
                    start_date=data.start_date,
                    end_date=data.end_date,
                    ip_count=data.ip_count,
                    root_count=data.root_count,
                    sub_count=data.sub_count,
                    ports_count=data.num_ports,  # num_ports input -> ports_count
                    creds_count=data.creds_count,
                    breach_count=data.breach_count,
                    cred_password_count=data.cred_password_count,
                    domain_alert_count=data.domain_alert_count,
                    suspected_domain_count=data.suspected_domain_count,
                    insecure_port_count=data.insecure_port_count,
                    verified_vuln_count=data.verified_vuln_count,
                    suspected_vuln_count=data.suspected_vuln_count,
                    suspected_vuln_addrs_count=data.suspected_vuln_addrs_count,
                    threat_actor_count=data.threat_actor_count,
                    dark_web_alerts_count=data.dark_web_alerts_count,
                    dark_web_mentions_count=data.dark_web_mentions_count,
                    dark_web_executive_alerts_count=data.dark_web_executive_alerts_count,
                    dark_web_asset_alerts_count=data.dark_web_asset_alerts_count,
                    pe_number_score=data.pe_number_score,
                    pe_letter_grade=data.pe_letter_grade,
                    cidr_count=data.cidr_count,
                    port_protocol_count=data.port_protocol_count,
                    software_count=data.software_count,
                    foreign_ips_count=data.foreign_ips_count,
                )
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_subs(), Issue 633 (paginated) ---
@api_router.post(
    "/sub_domains_by_org",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.SubDomainPagedTaskResp,
    tags=["Get all sub domains for a specified organization."],
)
def sub_domains_by_org(
    data: schemas.SubDomainPagedInput, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all sub domains for a specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = sub_domains_by_org_task.delay(data.org_uid, data.page, data.per_page)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/sub_domains_by_org/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.SubDomainPagedTaskResp,
    tags=["Check task status for subdomains by org query."],
)
async def sub_domains_by_org_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for sub_domains_by_org."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = sub_domains_by_org_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_previous_period(), Issue 634 ---
@api_router.post(
    "/rss_prev_period",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.RSSPrevPeriod],
    tags=[
        "Get previous report period report_summary_stats data for the specified organization"
    ],
)
def rss_prev_period(
    data: schemas.RSSPrevPeriodInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get previous period report_summary_stats data for the specified organization."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid
            # Make query
            rss_prev_period_data = list(
                ReportSummaryStats.objects.filter(
                    organizations_uid=data.org_uid, end_date=data.prev_end_date
                ).values(
                    "ip_count",
                    "root_count",
                    "sub_count",
                    "cred_password_count",
                    "suspected_vuln_addrs_count",
                    "suspected_vuln_count",
                    "insecure_port_count",
                    "threat_actor_count",
                )
            )
            return rss_prev_period_data
        except Exception:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- pescore_hist_domain_alert(), Issue 635 ---
@api_router.post(
    "/pescore_hist_domain_alert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDomainAlertTaskResp,
    tags=["Get all historical domain alert data for PE score."],
)
def pescore_hist_domain_alert(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score domain alert data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_hist_domain_alert_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_hist_domain_alert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDomainAlertTaskResp,
    tags=["Check task status for pescore_hist_domain_alert endpoint task."],
)
async def pescore_hist_domain_alert_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of pescore_hist_domain_alert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_hist_domain_alert_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- pescore_hist_darkweb_alert(), Issue 635 ---
@api_router.post(
    "/pescore_hist_darkweb_alert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDarkwebAlertTaskResp,
    tags=["Get all historical darkweb alert data for PE score."],
)
def pescore_hist_darkweb_alert(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score dark web alert data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_hist_darkweb_alert_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_hist_darkweb_alert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDarkwebAlertTaskResp,
    tags=["Check task status for pescore_hist_darkweb_alert endpoint task."],
)
async def pescore_hist_darkweb_alert_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of pescore_hist_darkweb_alert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_hist_darkweb_alert_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- pescore_hist_darkweb_ment(), Issue 635 ---
@api_router.post(
    "/pescore_hist_darkweb_ment",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDarkwebMentTaskResp,
    tags=["Get all historical darkweb mention data for PE score."],
)
def pescore_hist_darkweb_ment(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score dark web mention data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_hist_darkweb_ment_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_hist_darkweb_ment/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistDarkwebMentTaskResp,
    tags=["Check task status for pescore_hist_darkweb_ment endpoint task."],
)
async def pescore_hist_darkweb_ment_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of pescore_hist_darkweb_ment task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_hist_darkweb_ment_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- pescore_hist_cred(), Issue 635 ---
@api_router.post(
    "/pescore_hist_cred",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistCredTaskResp,
    tags=["Get all historical credential data for PE score."],
)
def pescore_hist_cred(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score credential data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_hist_cred_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_hist_cred/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreHistCredTaskResp,
    tags=["Check task status for pescore_hist_cred endpoint task."],
)
async def pescore_hist_cred_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of pescore_hist_cred task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_hist_cred_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- pescore_base_metrics(), Issue 635 ---
@api_router.post(
    "/pescore_base_metrics",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreBaseMetricsTaskResp,
    tags=["Get all base metric data for PE score."],
)
def pescore_base_metrics(
    data: schemas.GenInputDateRange, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get the PE score base metric data for a specified time period."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = pescore_base_metrics_task.delay(data.start_date, data.end_date)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pescore_base_metrics/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.PEScoreBaseMetricsTaskResp,
    tags=["Check task status for pescore_base_metrics endpoint task."],
)
async def pescore_base_metrics_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of pescore_base_metrics task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = pescore_base_metrics_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_new_cves_list(), Issue 636 ---
@api_router.get(
    "/pescore_check_new_cve",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.VwPEScoreCheckNewCVE],
    tags=["Get any detected CVEs that aren't in the cve_info table yet."],
)
def pescore_check_new_cve(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get any detected CVEs that aren't in the cve_info table yet."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            pescore_check_new_cve_data = list(
                VwPEScoreCheckNewCVE.objects.values("cve_name")
            )
            return pescore_check_new_cve_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- upsert_new_cves(), Issue 637 ---
@api_router.post(
    "/cve_info_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CVEInfoInsertTaskResp,
    tags=["Upsert new CVEs into the cve_info table"],
)
def cve_info_insert(
    data: schemas.CVEInfoInsertInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to insert new CVEs into the cve_info table."""
    # Convert list of input models to list of dictionaries
    new_cves = [dict(input_dict) for input_dict in data.new_cves]
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = cve_info_insert_task.delay(new_cves)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/cve_info_insert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CVEInfoInsertTaskResp,
    tags=["Check task status for cve_info_insert endpoint task."],
)
async def cve_info_insert_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of cve_info_insert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = cve_info_insert_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_intelx_breaches(), Issue 641 ---
@api_router.post(
    "/cred_breach_intelx",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CredBreachIntelXTaskResp,
    tags=["Get IntelX credential breaches"],
)
def cred_breach_intelx(
    data: schemas.CredBreachIntelXInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get IntelX credential breaches."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = cred_breach_intelx_task.delay(data.source_uid)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/cred_breach_intelx/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CredBreachIntelXTaskResp,
    tags=["Check task status for cred_breach_intelx endpoint task."],
)
async def cred_breach_intelx_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of cred_breach_intelx task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = cred_breach_intelx_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_sixgill_alerts(), Issue 653 ---
@api_router.post(
    "/alerts_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.AlertsInsertTaskResp,
    tags=["Insert multiple sixgill records into the alerts table."],
)
def alerts_insert(data: schemas.AlertsInsertInput, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to insert multiple sixgill records into the alerts table."""
    # Convert list of alert models to list of dictionaries
    new_alerts = [dict(input_dict) for input_dict in data.new_alerts]
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = alerts_insert_task.delay(new_alerts)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/alerts_insert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.AlertsInsertTaskResp,
    tags=["Check task status for alerts_insert endpoint task."],
)
async def alerts_insert_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of alerts_insert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = alerts_insert_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_sixgill_mentions(), Issue 654 ---
@api_router.post(
    "/mentions_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.MentionsInsertTaskResp,
    tags=["Insert multiple records into the mentions table."],
)
def mentions_insert(
    data: schemas.MentionsInsertInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to insert multiple records into the mentions table."""
    # Convert list of alert models to list of dictionaries
    new_mentions = [dict(input_dict) for input_dict in data.new_mentions]
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = mentions_insert_task.delay(new_mentions)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/mentions_insert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.MentionsInsertTaskResp,
    tags=["Check task status for mentions_insert endpoint task."],
)
async def mentions_insert_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of mentions_insert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = mentions_insert_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_sixgill_breaches(), Issue 655 ---
@api_router.post(
    "/cred_breaches_sixgill_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CredBreachesSixgillInsertTaskResp,
    tags=["Insert multiple records into the credential_breaches table."],
)
def cred_breaches_sixgill_insert(
    data: schemas.CredBreachesSixgillInsertInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to insert multiple records into the credential_breaches table."""
    # Convert list of alert models to list of dictionaries
    new_breaches = [dict(input_dict) for input_dict in data.new_breaches]
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = cred_breach_sixgill_task.delay(new_breaches)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/cred_breaches_sixgill_insert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CredBreachesSixgillInsertTaskResp,
    tags=["Check task status for cred_breaches_sixgill_insert endpoint task."],
)
async def cred_breaches_sixgill_insert_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of cred_breaches_sixgill_insert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = cred_breach_sixgill_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_sixgill_credentials(), Issue 656 ---
@api_router.post(
    "/cred_exp_sixgill_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CredExpSixgillInsertTaskResp,
    tags=["Insert multiple records into the credential_exposures table."],
)
def cred_exp_sixgill_insert(
    data: schemas.CredExpSixgillInsertInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to insert multiple records into the credential_exposures table."""
    # Convert list of alert models to list of dictionaries
    new_exposures = [dict(input_dict) for input_dict in data.new_exposures]
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = cred_exp_sixgill_task.delay(new_exposures)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/cred_exp_sixgill_insert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CredExpSixgillInsertTaskResp,
    tags=["Check task status for cred_exp_sixgill_insert endpoint task."],
)
async def cred_exp_sixgill_insert_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to get status of cred_exp_sixgill_insert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = cred_exp_sixgill_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_sixgill_topCVEs(), Issue 657 ---
@api_router.post(
    "/top_cves_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.TopCVEsInsertTaskResp,
    tags=["Insert multiple records into the top_cves table."],
)
def top_cves_insert(
    data: schemas.TopCVEsInsertInput, tokens: dict = Depends(get_api_key)
):
    """Call API endpoint to insert multiple records into the top_cves table."""
    # Convert list of models to list of dictionaries
    new_topcves = [dict(input_dict) for input_dict in data.new_topcves]
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = top_cves_insert_task.delay(new_topcves)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/top_cves_insert/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.TopCVEsInsertTaskResp,
    tags=["Check task status for top_cves_insert endpoint task."],
)
async def top_cves_insert_status(task_id: str, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get status of top_cves_insert task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = top_cves_insert_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- execute_dnsmonitor_data(), Issue 659
@api_router.put(
    "/domain_permu_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert multiple DNSMonitor records into the domain_permutations table."],
)
def domain_permu_insert(
    data: schemas.DomainPermuInsertInput, tokens: dict = Depends(get_api_key)
):
    """Insert multiple DNSMonitor records into the domain_permutations table through the API."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, proceed
            create_ct = 0
            update_ct = 0
            for record in data.insert_data:
                # convert to dict
                record_dict = dict(record)
                curr_org_inst = Organizations.objects.get(
                    organizations_uid=record_dict["organizations_uid"]
                )
                curr_source_inst = DataSource.objects.get(
                    data_source_uid=record_dict["data_source_uid"]
                )
                curr_subdomain_inst = SubDomains.objects.get(
                    sub_domain_uid=record_dict["sub_domain_uid"]
                )
                # Insert each row of data, on conflict update existing
                try:
                    DomainPermutations.objects.get(
                        organizations_uid=curr_org_inst,
                        domain_permutation=record_dict["domain_permutation"],
                    )
                    # If record already exists, update
                    DomainPermutations.objects.filter(
                        organizations_uid=curr_org_inst,
                        domain_permutation=record_dict["domain_permutation"],
                    ).update(
                        ipv4=record_dict["ipv4"],
                        ipv6=record_dict["ipv6"],
                        date_observed=record_dict["date_observed"],
                        mail_server=record_dict["mail_server"],
                        name_server=record_dict["name_server"],
                        sub_domain_uid=curr_subdomain_inst,
                        data_source_uid=curr_source_inst,
                    )
                    update_ct += 1
                except DomainPermutations.DoesNotExist:
                    # Otherwise, create new record
                    DomainPermutations.objects.create(
                        organizations_uid=curr_org_inst,
                        domain_permutation=record_dict["domain_permutation"],
                        ipv4=record_dict["ipv4"],
                        ipv6=record_dict["ipv6"],
                        date_observed=record_dict["date_observed"],
                        mail_server=record_dict["mail_server"],
                        name_server=record_dict["name_server"],
                        sub_domain_uid=curr_subdomain_inst,
                        data_source_uid=curr_source_inst,
                    )
                    create_ct += 1
            return (
                "New DNSMonitor data in the domain_permutations table: "
                + str(create_ct)
                + " created, "
                + str(update_ct)
                + " updated"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- execute_dnsmonitor_alert_data(), Issue 660
@api_router.put(
    "/domain_alerts_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert multiple DNSMonitor records into the domain_alerts table."],
)
def domain_alerts_insert(
    data: schemas.DomainAlertsInsertInput, tokens: dict = Depends(get_api_key)
):
    """Insert multiple DNSMonitor records into the domain_alerts table through the API."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, proceed
            create_ct = 0
            for record in data.insert_data:
                # convert to dict
                record_dict = dict(record)
                curr_sub_inst = SubDomains.objects.get(
                    sub_domain_uid=record_dict["sub_domain_uid"]
                )
                curr_source_inst = DataSource.objects.get(
                    data_source_uid=record_dict["data_source_uid"]
                )
                # Insert each row of data, on conflict do nothing
                try:
                    DomainAlerts.objects.get(
                        alert_type=record_dict["alert_type"],
                        sub_domain_uid=record_dict["sub_domain_uid"],
                        date=record_dict["date"],
                        new_value=record_dict["new_value"],
                    )
                    # If record already exists, do nothing
                except DomainAlerts.DoesNotExist:
                    # Otherwise, create new record
                    DomainAlerts.objects.create(
                        domain_alert_uid=uuid.uuid1(),
                        organizations_uid=record_dict["organizations_uid"],
                        sub_domain_uid=curr_sub_inst,
                        data_source_uid=curr_source_inst,
                        alert_type=record_dict["alert_type"],
                        message=record_dict["message"],
                        previous_value=record_dict["previous_value"],
                        new_value=record_dict["new_value"],
                        date=record_dict["date"],
                    )
                    create_ct += 1
            return (
                str(create_ct)
                + " DNSMonitor records created in the domain_alerts table"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- addRootdomain(), Issue 661 ---
@api_router.put(
    "/root_domains_single_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert a single root domain into the root_domains table."],
)
def root_domains_single_insert(
    data: schemas.RootDomainsSingleInsertInput, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to insert a single root domain into the root_domains table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, insert root domain
            # Check if record already exists
            domain_results = RootDomains.objects.filter(
                root_domain=data.root_domain,
                organizations_uid=data.pe_org_uid,
                data_source_uid=data.source_uid,
            )
            if not domain_results.exists():
                # If not, insert new record
                curr_org_inst = Organizations.objects.get(
                    organizations_uid=data.pe_org_uid
                )
                curr_source_inst = DataSource.objects.get(
                    data_source_uid=data.source_uid
                )
                try:
                    ip = socket.gethostbyname(data.root_domain)
                except Exception:
                    ip = None
                RootDomains.objects.create(
                    root_domain=data.root_domain,
                    organizations_uid=curr_org_inst,
                    data_source_uid=curr_source_inst,
                    ip_address=ip,
                )
                return (
                    "Root domain has been inserted into root_domains table for "
                    + data.org_name
                )
            return (
                "Root domain already exists in root_domains table for " + data.org_name
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- addSubdomain(), Issue 662 ---
@api_router.put(
    "/sub_domains_single_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # , Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert a single sub domain into the sub_domains table."],
)
def sub_domains_single_insert(
    data: schemas.SubDomainsSingleInsertInput, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to insert a single sub domain into the sub_domains table."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, proceed
            if data.root:
                # If sub domain is also a root domain
                curr_root = data.domain
            else:
                # If sub domain is not a root domain
                curr_root = data.domain.split(".")[-2]
                curr_root = ".".join(curr_root)
            curr_date = datetime.today().strftime("%Y-%m-%d")
            org_name = Organizations.objects.filter(
                organizations_uid=data.pe_org_uid
            ).values("cyhy_db_name")[0]["cyhy_db_name"]
            create_ct = 0
            update_ct = 0
            # Check if sub domain already exists in table
            sub_domain_results = SubDomains.objects.filter(
                sub_domain=data.domain,
                root_domain_uid__organizations_uid=data.pe_org_uid,
            )
            if not sub_domain_results.exists():
                # If not, insert new record
                # Get data_source instance of "findomain"
                findomain_inst = DataSource.objects.get(name="findomain")
                # Check if root domain already exists
                root_results = RootDomains.objects.filter(
                    organizations_uid=data.pe_org_uid, root_domain=curr_root
                )
                if not root_results.exists():
                    # If root domain does not exist, create a new record
                    RootDomains.objects.create(
                        organizations_uid=Organizations.objects.get(
                            organizations_uid=data.pe_org_uid
                        ),
                        root_domain=curr_root,
                        data_source_uid=findomain_inst,
                        enumerate_subs=False,
                    )
                # Get root_domains instance of specified root domain
                root_inst = RootDomains.objects.get(
                    organizations_uid=data.pe_org_uid, root_domain=curr_root
                )
                # Create subdomain record now that root exists
                SubDomains.objects.create(
                    sub_domain=data.domain,
                    root_domain_uid=root_inst,
                    data_source_uid=findomain_inst,
                    first_seen=curr_date,
                    last_seen=curr_date,
                    identified=False,
                )
                create_ct += 1
            else:
                # If subdomain record already exists, update
                SubDomains.objects.filter(
                    sub_domain=data.domain,
                    root_domain_uid__organizations_uid=data.pe_org_uid,
                ).update(
                    last_seen=curr_date,
                    identified=False,
                )
                update_ct += 1
            # Return status message
            return (
                str(create_ct)
                + " records created, "
                + str(update_ct)
                + " records updated in the sub_domains table for "
                + org_name
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_intelx_breaches(), Issue 663 ---
@api_router.put(
    "/cred_breaches_intelx_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert IntelX credential breaches into the credential_breaches table."],
)
def cred_breaches_intelx_insert(
    data: schemas.CredBreachesIntelxInsertInput, tokens: dict = Depends(get_api_key)
):
    """Insert IntelX credential breaches into the credential_breaches table through the API ."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, insert intelx breach data
            insert_count = 0
            update_count = 0
            for row in data.breach_data:
                # Check if record already exists
                row_dict = row.__dict__
                breach_results = CredentialBreaches.objects.filter(
                    breach_name=row_dict["breach_name"]
                )
                if not breach_results.exists():
                    # If not, insert new record
                    curr_data_source_inst = DataSource.objects.get(
                        data_source_uid=row_dict["data_source_uid"]
                    )
                    CredentialBreaches.objects.create(
                        breach_name=row_dict["breach_name"],
                        description=row_dict["description"],
                        breach_date=row_dict["breach_date"],
                        added_date=row_dict["added_date"],
                        modified_date=row_dict["modified_date"],
                        password_included=row_dict["password_included"],
                        data_source_uid=curr_data_source_inst,
                    )
                    insert_count += 1
                else:
                    CredentialBreaches.objects.filter(
                        breach_name=row_dict["breach_name"]
                    ).update(password_included=row_dict["password_included"])
                    update_count += 1
            return (
                str(insert_count)
                + " records created, "
                + str(update_count)
                + " records updated in the credential_breaches table"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- insert_intelx_credentials(), Issue 664 ---
@api_router.put(
    "/cred_exp_intelx_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert IntelX data into the credential_exposures table."],
)
def cred_exp_intelx_insert(
    data: schemas.CredExpIntelxInsertInput, tokens: dict = Depends(get_api_key)
):
    """Insert IntelX data into the credential_exposures table using the API endpoint."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, insert intelx data
            create_cnt = 0
            update_cnt = 0
            for row in data.exp_data:
                row_dict = row.__dict__
                try:
                    CredentialExposures.objects.get(
                        breach_name=row_dict["breach_name"],
                        email=row_dict["email"],
                    )
                    # If record already exists, update
                    CredentialExposures.objects.filter(
                        breach_name=row_dict["breach_name"],
                        email=row_dict["email"],
                    ).update(modified_date=row_dict["modified_date"])
                    update_cnt += 1
                except CredentialExposures.DoesNotExist:
                    # If record doesn't exist yet, create one
                    curr_org_inst = Organizations.objects.get(
                        organizations_uid=row_dict["organizations_uid"]
                    )
                    curr_source_inst = DataSource.objects.get(
                        data_source_uid=row_dict["data_source_uid"]
                    )
                    curr_breach_inst = CredentialBreaches.objects.get(
                        breach_name=row_dict["breach_name"],
                    )
                    CredentialExposures.objects.create(
                        # credential_exposures_uid=uuid.uuid1(),
                        email=row_dict["email"],
                        organizations_uid=curr_org_inst,
                        root_domain=row_dict["root_domain"],
                        sub_domain=row_dict["sub_domain"],
                        breach_name=row_dict["breach_name"],
                        modified_date=row_dict["modified_date"],
                        data_source_uid=curr_source_inst,
                        password=row_dict["password"],
                        hash_type=row_dict["hash_type"],
                        intelx_system_id=row_dict["intelx_system_id"],
                        credential_breaches_uid=curr_breach_inst,
                    )
                    create_cnt += 1
            # Return success message
            return (
                str(create_cnt)
                + " records created, "
                + str(update_cnt)
                + " records updated in the credential_exposures table"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- xpanse endpoint, Issue 682 ---
@api_router.put(
    "/xpanse_business_unit_insert_or_update",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.PshttDataBase],
    tags=["Update or insert CVE data from NIST"],
)
# @transaction.atomic
def xpanse_business_unit_insert_or_update(
    # tag: str,
    data: schemas.XpanseBusinessUnitsInsert,
    tokens: dict = Depends(get_api_key),
):
    """Create API endpoint to create a record in database."""
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            LOGGER.info(f"The api key submitted {tokens}")

            (
                business_unit_object,
                created,
            ) = XpanseBusinessUnits.objects.update_or_create(
                entity_name=data.entity_name,
                defaults={
                    "state": data.state,
                    "county": data.county,
                    "city": data.city,
                    "sector": data.sector,
                    "entity_type": data.entity_type,
                    "region": data.region,
                    "rating": data.rating,
                },
            )
            if created:
                LOGGER.info(
                    "New Xpanse Business Unit record created for %s", data.entity_name
                )
                return {
                    "message": "New business unit created.",
                    "business_unit_obj": business_unit_object,
                }
            return {
                "message": "Business unit updated.",
                "business_unit_obj": business_unit_object,
            }
        except Exception as e:
            print(e)
            print("failed to insert or update")
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- xpanse endpoint, Issue 682 ---
@api_router.put(
    "/xpanse_alert_insert_or_update",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.PshttDataBase],
    tags=["Update or insert CVE data from NIST"],
)
# @transaction.atomic
def xpanse_alert_insert_or_update(
    # tag: str,
    data: schemas.XpanseAlertInsert,
    tokens: dict = Depends(get_api_key),
):
    """Create API endpoint to create a record in database."""
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            LOGGER.info(f"The api key submitted {tokens}")
            LOGGER.info("Got into Xpanse Alert insert")

            # vender_prod_dict = data.vender_product
            alert_object, created = XpanseAlerts.objects.update_or_create(
                alert_id=data.alert_id,
                defaults={
                    "time_pulled_from_xpanse": data.time_pulled_from_xpanse,
                    # "alert_id": data.alert_id,
                    "detection_timestamp": data.detection_timestamp,
                    "alert_name": data.alert_name,
                    "description": data.description,
                    "host_name": data.host_name,
                    "alert_action": data.alert_action,
                    "action_pretty": data.action_pretty,
                    "action_country": data.action_country,
                    "action_remote_port": data.action_remote_port,
                    "starred": data.starred,
                    "external_id": data.external_id,
                    "related_external_id": data.related_external_id,
                    "alert_occurrence": data.alert_occurrence,
                    "severity": data.severity,
                    "matching_status": data.matching_status,
                    "local_insert_ts": data.local_insert_ts,
                    "last_modified_ts": data.last_modified_ts,
                    "case_id": data.case_id,
                    "event_timestamp": data.event_timestamp,
                    "alert_type": data.alert_type,
                    "resolution_status": data.resolution_status,
                    "resolution_comment": data.resolution_comment,
                    "tags": data.tags,
                    "last_observed": data.last_observed,
                    "country_codes": data.country_codes,
                    "cloud_providers": data.cloud_providers,
                    "ipv4_addresses": data.ipv4_addresses,
                    "domain_names": data.domain_names,
                    "service_ids": data.service_ids,
                    "website_ids": data.website_ids,
                    "asset_ids": data.asset_ids,
                    "certificate": data.certificate,
                    "port_protocol": data.port_protocol,
                    "attack_surface_rule_name": data.attack_surface_rule_name,
                    "remediation_guidance": data.remediation_guidance,
                    "asset_identifiers": data.asset_identifiers
                    # business_units: Optional[List[str]] = None
                    # services: Optional[List[XpanseService]] = None
                    # assets : Optional[List[XpanseAsset]] = None
                },
            )

            if created:
                LOGGER.info("new Xpanse alert record created for %s", data.alert_name)

            business_unit_list = []
            for b_u in data.business_units:
                business_unit_list.append(
                    XpanseBusinessUnits.objects.get(entity_name=b_u)
                )

            alert_object.business_units.set(business_unit_list)

            asset_list = []
            for asset_data in data.assets:
                asset_object, created = XpanseAssets.objects.update_or_create(
                    asm_id=asset_data.asm_id,
                    defaults={
                        "asset_name": asset_data.asset_name,
                        "asset_type": asset_data.asset_type,
                        "last_observed": asset_data.last_observed,
                        "first_observed": asset_data.first_observed,
                        "externally_detected_providers": asset_data.externally_detected_providers,
                        "created": asset_data.created,
                        "ips": asset_data.ips,
                        "active_external_services_types": asset_data.active_external_services_types,
                        "domain": asset_data.domain,
                        "certificate_issuer": asset_data.certificate_issuer,
                        "certificate_algorithm": asset_data.certificate_algorithm,
                        "certificate_classifications": asset_data.certificate_classifications,
                        "resolves": asset_data.resolves,
                        # details
                        "top_level_asset_mapper_domain": asset_data.top_level_asset_mapper_domain,
                        "domain_asset_type": asset_data.domain_asset_type,
                        "is_paid_level_domain": asset_data.is_paid_level_domain,
                        "domain_details": asset_data.domain_details,
                        "dns_zone": asset_data.dns_zone,
                        "latest_sampled_ip": asset_data.latest_sampled_ip,
                        "recent_ips": asset_data.recent_ips,
                        "external_services": asset_data.external_services,
                        "externally_inferred_vulnerability_score": asset_data.externally_inferred_vulnerability_score,
                        "externally_inferred_cves": asset_data.externally_inferred_cves,
                        "explainers": asset_data.explainers,
                        "tags": asset_data.tags,
                    },
                )
                asset_list.append(asset_object)

            alert_object.assets.set(asset_list)

            services_list = []
            for service_data in data.services:
                service_object, created = XpanseServices.objects.update_or_create(
                    service_id=service_data.service_id,
                    defaults={
                        "service_name": service_data.service_name,
                        "service_type": service_data.service_type,
                        "ip_address": service_data.ip_address,
                        "domain": service_data.domain,
                        "externally_detected_providers": service_data.externally_detected_providers,
                        "is_active": service_data.is_active,
                        "first_observed": service_data.first_observed,
                        "last_observed": service_data.last_observed,
                        "port": service_data.port,
                        "protocol": service_data.protocol,
                        "active_classifications": service_data.active_classifications,
                        "inactive_classifications": service_data.inactive_classifications,
                        "discovery_type": service_data.discovery_type,
                        "externally_inferred_vulnerability_score": service_data.externally_inferred_vulnerability_score,
                        "externally_inferred_cves": service_data.externally_inferred_cves,
                        "service_key": service_data.service_key,
                        "service_key_type": service_data.service_key_type,
                    },
                )
                LOGGER.info(service_data)
                if service_data.cves is not None:
                    for cve_data, cve_match_data in service_data.cves:
                        LOGGER.info(cve_data)
                        LOGGER.info(cve_match_data)
                        cve_object, created = XpanseCves.objects.update_or_create(
                            cve_id=cve_data.cve_id,
                            defaults={
                                "cvss_score_v2": cve_data.cvss_score_v2,
                                "cve_severity_v2": cve_data.cve_severity_v2,
                                "cvss_score_v3": cve_data.cvss_score_v3,
                                "cve_severity_v3": cve_data.cve_severity_v3,
                            },
                        )

                        (
                            cve_match_object,
                            created,
                        ) = XpanseCveService.objects.update_or_create(
                            xpanse_inferred_cve=cve_object,
                            xpanse_service=service_object,
                            defaults={
                                "inferred_cve_match_type": cve_match_data.inferred_cve_match_type,
                                "product": cve_match_data.product,
                                "confidence": cve_match_data.confidence,
                                "vendor": cve_match_data.vendor,
                                "version_number": cve_match_data.version_number,
                                "activity_status": cve_match_data.activity_status,
                                "first_observed": cve_match_data.first_observed,
                                "last_observed": cve_match_data.last_observed,
                            },
                        )
                    services_list.append(service_object)

            alert_object.services.set(services_list)

            alert_object.save()

            # for vender, product_list in vender_prod_dict.items():

            #     vender_obj, vender_created = CpeVender.objects.update_or_create(
            #         vender_name=vender
            #     )
            #     for product, version in product_list:
            #         product_obj, product_created = CpeProduct.objects.update_or_create(
            #             cpe_product_name=product,
            #             version_number=version,
            #             defaults={"cpe_vender_uid": vender_obj},
            #         )
            #         prod_obj_list.append(product_obj)

            # cve_object.products.set(prod_obj_list)
            # cve_object.save()

            # prods = []
            # for prod in list(cve_object.products.all()):
            #     prods.append(
            #         {
            #             "cpe_product_uid": prod.cpe_product_uid,
            #             "cpe_product_name": prod.cpe_product_name,
            #             "version_number": prod.version_number,
            #             "vender_uid": prod.cpe_vender_uid_id,
            #             "vender_name": prod.cpe_vender_uid.vender_name,
            #         }
            #     )
            return {"message": "Record updated successfully.", "alerts": alert_object}

        except Exception as e:
            LOGGER.error(e)
            print("failed to insert or update")
            LOGGER.info("API key expired please try again")

    else:
        return {"message": "No api key was submitted"}


# --- xpanse endpoint, Issue 682 ---
@api_router.post(
    "/xpanse_vulns",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.XpanseVulnPullTaskResp,
    tags=["Get all VS cert data needed for D-Score"],
)
def xpanse_vulns(
    data: schemas.XpanseVulnPullInput, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all Xpanse Vulnerabilities."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    LOGGER.info(data)
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_xpanse_vulns.delay(data.business_unit, data.modified_datetime)
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- xpanse endpoint, Issue 682 ---
@api_router.get(
    "/xpanse_vulns/task/{task_id}",
    dependencies=[Depends(get_api_key), Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.XpanseVulnPullTaskResp,
    tags=["Check task status for Xpanse Vulnerability pull."],
)
async def get_xpanse_vulns_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Check task status for Xpanse Vulnerability pull."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = get_xpanse_vulns.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- NIST CVE endpoint, Issue 696 ---
@api_router.put(
    "/cve_insert_or_update",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.PshttDataBase],
    tags=["Update or insert CVE data from NIST"],
)
# @transaction.atomic
def cve_insert_or_update(
    # tag: str,
    data: schemas.CveInsert,
    tokens: dict = Depends(get_api_key),
):
    """Create API endpoint to create a record in database."""
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            LOGGER.info(f"The api key submitted {tokens}")
            # Get WAS record based on tag
            vender_prod_dict = data.vender_product
            cve_object, created = Cves.objects.update_or_create(
                cve_name=data.cve_name,
                defaults={
                    "cve_name": data.cve_name,
                    "published_date": data.published_date,
                    "last_modified_date": data.last_modified_date,
                    "vuln_status": data.vuln_status,
                    "description": data.description,
                    "cvss_v2_source": data.cvss_v2_source,
                    "cvss_v2_type": data.cvss_v2_type,
                    "cvss_v2_version": data.cvss_v2_version,
                    "cvss_v2_vector_string": data.cvss_v2_vector_string,
                    "cvss_v2_base_score": data.cvss_v2_base_score,
                    "cvss_v2_base_severity": data.cvss_v2_base_severity,
                    "cvss_v2_exploitability_score": data.cvss_v2_exploitability_score,
                    "cvss_v2_impact_score": data.cvss_v2_impact_score,
                    "cvss_v3_source": data.cvss_v3_source,
                    "cvss_v3_type": data.cvss_v3_type,
                    "cvss_v3_version": data.cvss_v3_version,
                    "cvss_v3_vector_string": data.cvss_v3_vector_string,
                    "cvss_v3_base_score": data.cvss_v3_base_score,
                    "cvss_v3_base_severity": data.cvss_v3_base_severity,
                    "cvss_v3_exploitability_score": data.cvss_v3_exploitability_score,
                    "cvss_v3_impact_score": data.cvss_v3_impact_score,
                    "cvss_v4_source": data.cvss_v4_source,
                    "cvss_v4_type": data.cvss_v4_type,
                    "cvss_v4_version": data.cvss_v4_version,
                    "cvss_v4_vector_string": data.cvss_v4_vector_string,
                    "cvss_v4_base_score": data.cvss_v4_base_score,
                    "cvss_v4_base_severity": data.cvss_v4_base_severity,
                    "cvss_v4_exploitability_score": data.cvss_v4_exploitability_score,
                    "cvss_v4_impact_score": data.cvss_v4_impact_score,
                    "weaknesses": data.weaknesses,
                    "reference_urls": data.reference_urls,
                    "cpe_list": data.cpe_list,
                },
            )
            if created:
                LOGGER.info("new CVE record created for %s", data.cve_name)

            prod_obj_list = []
            for vender, product_list in vender_prod_dict.items():
                vender_obj, vender_created = CpeVender.objects.update_or_create(
                    vender_name=vender
                )
                for product, version in product_list:
                    product_obj, product_created = CpeProduct.objects.update_or_create(
                        cpe_product_name=product,
                        version_number=version,
                        defaults={"cpe_vender_uid": vender_obj},
                    )
                    prod_obj_list.append(product_obj)

            cve_object.products.set(prod_obj_list)
            cve_object.save()

            prods = []
            for prod in list(cve_object.products.all()):
                prods.append(
                    {
                        "cpe_product_uid": prod.cpe_product_uid,
                        "cpe_product_name": prod.cpe_product_name,
                        "version_number": prod.version_number,
                        "vender_uid": prod.cpe_vender_uid_id,
                        "vender_name": prod.cpe_vender_uid.vender_name,
                    }
                )
            return {
                "message": "Record updated successfully.",
                "updated_cve": cve_object,
                "products": prods,
            }

        except Exception as e:
            print(e)
            print("failed to insert or update")
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- NIST CVE endpoint, Issue 696 ---
@api_router.post(
    "/get_cve",
    dependencies=[Depends(get_api_key)],
    # response_model=schemas.DataSource,
    tags=["Get cve data and relevant products for a gvien CVE"],
)
def get_cve(data: schemas.GetCveCall, tokens: dict = Depends(get_api_key)):
    """Get CVE and product data."""
    LOGGER.info("in CVE")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            LOGGER.info(f"The api key submitted {tokens}")
            try:
                cve = Cves.objects.get(cve_name=f"{data.cve_name}")
                products = cve.products.all()
                vend_prod_dict: dict[str, list] = {}
                for prod in products.iterator():
                    if prod.cpe_vender_uid.vender_name not in vend_prod_dict.keys():
                        vend_prod_dict[prod.cpe_vender_uid.vender_name] = []
                    vend_prod_dict[prod.cpe_vender_uid.vender_name].append(
                        {
                            "cpe_product_uid": prod.cpe_product_uid,
                            "cpe_product_name": prod.cpe_product_name,
                            "version_number": prod.version_number,
                            "vender_uid": prod.cpe_vender_uid_id,
                        }
                    )
                cve_dict = model_to_dict(cve)
                return {"cve_data": cve_dict, "products": vend_prod_dict}
            except ValidationError:
                return {"message": "CVE does not exist"}

        except Exception as e:
            LOGGER.info("API key expired please try again")
            LOGGER.info(e)
    else:
        return {"message": "No api key was submitted"}


# --- NIST CVE endpoint, Issue 696 ---
@api_router.post(
    "/cves_by_modified_date",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CvePagedTaskResp,
    tags=["Get all CVEs and related products since a user specified date."],
)
def cves_by_modified_date(
    data: schemas.CvePagedInput, tokens: dict = Depends(get_api_key)
):
    """Create API endpoint to get all CVEs and related products since a user specified date."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = cves_by_modified_date_task.delay(
                data.modified_datetime, data.page, data.per_page
            )
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- NIST CVE endpoint, Issue 696 ---
@api_router.get(
    "/cves_by_modified_date/task/{task_id}",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=schemas.CvePagedTaskResp,
    tags=["Check task status for cves_by_modified_date."],
)
async def cves_by_modified_date_task_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Get task status for cves_by_modified_date."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # userapiTokenverify(theapiKey=tokens)
            # Retrieve task status
            task = cves_by_modified_date_task.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/pshtt_unscanned_domains",
    dependencies=[Depends(get_api_key)],
    response_model=schemas.PshttDomainToRunTaskResp,
    tags=["List of subdomains to run through PSHTT"],
)
def get_unscanned_pshtt_domains(tokens: dict = Depends(get_api_key)):
    """Create API endpoint to get current domains that have not been run through pshtt recently."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, create task for query
            task = get_vw_pshtt_domains_to_run_info.delay()
            # Return the new task id w/ "Processing" status
            return {"task_id": task.id, "status": "Processing"}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/pshtt_unscanned_domains/task/{task_id}",
    dependencies=[Depends(get_api_key)],
    # , Depends(RateLimiter(times=200, seconds=60))
    response_model=schemas.PshttDomainToRunTaskResp,
    tags=["Check task status for endpoint."],
)
async def get_pshtt_domains_to_run_status(
    task_id: str, tokens: dict = Depends(get_api_key)
):
    """Retrieve status of get_pshtt_domains_to_run task."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            # Retrieve task status
            task = get_vw_pshtt_domains_to_run_info.AsyncResult(task_id)
            # Return appropriate message for status
            if task.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "status": "Completed",
                    "result": task.result,
                }
            elif task.state == "PENDING":
                return {"task_id": task_id, "status": "Pending"}
            elif task.state == "FAILURE":
                return {
                    "task_id": task_id,
                    "status": "Failed",
                    "error": str(task.result),
                }
            else:
                return {"task_id": task_id, "status": task.state}
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}

# --- get_orgs(), Issue 699 pe-reports ---
@api_router.get(
    "/organizations_demo_or_report_on",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrganizationsFullTable],
    tags=["Retrieve data for all demo or report_on orgs."],
)
def organizations_demo(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get data for all demo or report_on orgs."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            organizations_demo_or_report_on_data = list(
                Organizations.objects.filter(Q(demo=True) | Q(report_on=True)).values()
            )
            # Convert data types to match response model
            for row in organizations_demo_or_report_on_data:
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
                row["cyhy_period_start"] = convert_date_to_string(
                    row["cyhy_period_start"]
                )
                row["date_first_reported"] = convert_date_to_string(
                    row["date_first_reported"]
                )
            return organizations_demo_or_report_on_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.put(
    "/pshtt_result_update_or_insert",
    dependencies=[Depends(get_api_key)],
    # response_model=Dict[schemas.PshttDataBase],
    tags=["Update or insert PSHTT data"],
)
# @transaction.atomic
def pshtt_result_update_or_insert(
    # tag: str,
    data: schemas.PshttInsert,
    tokens: dict = Depends(get_api_key),
):
    """Create API endpoint to create a record in database."""
    if tokens:
        try:
            print(data.organizations_uid)
            userapiTokenverify(theapiKey=tokens)
            LOGGER.info(f"The api key submitted {tokens}")
            data_source_uid = DataSource.objects.get(name="Pshtt")
            organization_uid = Organizations.objects.get(
                organizations_uid=data.organizations_uid
            )
            sub_domain_uid = SubDomains.objects.get(sub_domain_uid=data.sub_domain_uid)

            
            pshtt_object, created = PshttResults.objects.update_or_create(
                sub_domain_uid=data.sub_domain_uid,
                organizations_uid=data.organizations_uid,
                defaults={
                    "organizations_uid": organization_uid,
                    "sub_domain_uid": sub_domain_uid,
                    "data_source_uid": data_source_uid,
                    "sub_domain": data.sub_domain,
                    "date_scanned": data.date_scanned,
                    "base_domain": data.base_domain,
                    "base_domain_hsts_preloaded": data.base_domain_hsts_preloaded,
                    "canonical_url": data.canonical_url,
                    "defaults_to_https": data.defaults_to_https,
                    "domain": data.domain,
                    "domain_enforces_https": data.domain_enforces_https,
                    "domain_supports_https": data.domain_supports_https,
                    "domain_uses_strong_hsts": data.domain_uses_strong_hsts,
                    "downgrades_https": data.downgrades_https,
                    "htss": data.htss,
                    "hsts_entire_domain": data.hsts_entire_domain,
                    "hsts_header": data.hsts_header,
                    "hsts_max_age": data.hsts_max_age,
                    "hsts_preload_pending": data.hsts_preload_pending,
                    "hsts_preload_ready": data.hsts_preload_ready,
                    "hsts_preloaded": data.hsts_preloaded,
                    "https_bad_chain": data.https_bad_chain,
                    "https_bad_hostname": data.https_bad_hostname,
                    "https_cert_chain_length": data.https_cert_chain_length,
                    "https_client_auth_required": data.https_client_auth_required,
                    "https_custom_truststore_trusted": data.https_custom_truststore_trusted,
                    "https_expired_cert": data.https_expired_cert,
                    "https_full_connection": data.https_full_connection,
                    "https_live": data.https_live,
                    "https_probably_missing_intermediate_cert": data.https_probably_missing_intermediate_cert,
                    "https_publicly_trusted": data.https_publicly_trusted,
                    "https_self_signed_cert": data.https_self_signed_cert,
                    "https_leaf_cert_expiration_date": data.https_leaf_cert_expiration_date,
                    "https_leaf_cert_issuer": data.https_leaf_cert_issuer,
                    "https_leaf_cert_subject": data.https_leaf_cert_subject,
                    "https_root_cert_issuer": data.https_root_cert_issuer,
                    "ip": data.ip,
                    "live": data.live,
                    "notes": data.notes,
                    "redirect": data.redirect,
                    "redirect_to": data.redirect_to,
                    "server_header": data.server_header,
                    "server_version": data.server_version,
                    "strictly_forces_https": data.strictly_forces_https,
                    "unknown_error": data.unknown_error,
                    "valid_https": data.valid_https,
                    "ep_http_headers": data.ep_http_headers,
                    "ep_http_server_header": data.ep_http_server_header,
                    "ep_http_server_version": data.ep_http_server_version,
                    "ep_https_headers": data.ep_https_headers,
                    "ep_https_hsts_header": data.ep_https_hsts_header,
                    "ep_https_server_header": data.ep_https_server_header,
                    "ep_https_server_version": data.ep_https_server_version,
                    "ep_httpswww_headers": data.ep_httpswww_headers,
                    "ep_httpswww_hsts_header": data.ep_httpswww_hsts_header,
                    "ep_httpswww_server_header": data.ep_httpswww_server_header,
                    "ep_httpswww_server_version": data.ep_httpswww_server_version,
                    "ep_httpwww_headers": data.ep_httpwww_headers,
                    "ep_httpwww_server_header": data.ep_httpwww_server_header,
                    "ep_httpwww_server_version": data.ep_httpwww_server_version,
                },
            )
            print("made it past insert")
            if created:
                LOGGER.info("new PSHTT record created for %s", data.sub_domain)

            return {"message": "Record updated successfully.", "updated_data": data}

        except Exception as e:
            print(e)
            print("failed to insert or update")
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- get_data_source_uid(), Issue 700 pe-reports ---
@api_router.post(
    "/data_source_by_name",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.DataSourceFullTable],
    tags=["Retrieve data for specified data source name."],
)
def data_source_by_name(data: schemas.DataSourceByNameInput, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get data for specified data source name."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            data_source_by_name_data = list(
                DataSource.objects.filter(name=data.name).values()
            )
            # also update data source record
            today = dt.today().strftime("%Y-%m-%d")
            DataSource.objects.filter(name=data.name).update(last_run=today)
            # Convert data types to match response model
            for row in data_source_by_name_data:
                row["data_source_uid"] = convert_uuid_to_string(
                    row["data_source_uid"]
                )
                row["last_run"] = convert_date_to_string(
                    row["last_run"]
                )
            return data_source_by_name_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
    

# --- get_breaches(), Issue 701 pe-reports ---
@api_router.get(
    "/breach_names_and_uids",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.BreachNamesAndUIDs],
    tags=["Retrieve all breach names and uids."],
)
def breach_names_and_uids(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all breach names and uids."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            breach_names_and_uids_data = list(
                CredentialBreaches.objects.all().values("breach_name", "credential_breaches_uid")
            )
            # Convert data types to match response model
            for row in breach_names_and_uids_data:
                row["credential_breaches_uid"] = convert_uuid_to_string(
                    row["credential_breaches_uid"]
                )
            return breach_names_and_uids_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
    

# --- getSubdomain(), Issue 702 pe-reports ---
@api_router.post(
    "/subdomain_uid_by_domain",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.SubdomainUIDByDomain],
    tags=["Retrieve data for the specified subdomain."],
)
def subdomain_by_domain(data: schemas.SubdomainUIDByDomainInput, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get data for specified subdomain."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            subdomain_by_domain_data = list(
                SubDomains.objects.filter(sub_domain=data.domain).values("sub_domain_uid")
            )
            # Convert data types to match response model
            for row in subdomain_by_domain_data:
                row["sub_domain_uid"] = convert_uuid_to_string(row["sub_domain_uid"])
            return subdomain_by_domain_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
    

# --- org_root_domains(), Issue 703 pe-reports ---
@api_router.post(
    "/rootdomains_by_org_uid",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.RootDomainsTable],
    tags=["Retrieve root domains for the specified org uid."],
)
def rootdomains_by_org_uid(data: schemas.RootdomainsByOrgUIDInput, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get root domains for specified org uid."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            rootdomains_by_org_uid_data = list(
                RootDomains.objects.filter(
                    organizations_uid=data.org_uid, 
                    enumerate_subs=True
                ).values()
            )
            # Convert data types to match response model
            for row in rootdomains_by_org_uid_data:
                row["root_domain_uid"] = convert_uuid_to_string(row["root_domain_uid"])
                row["organizations_uid_id"] = convert_uuid_to_string(row["organizations_uid_id"])
                row["data_source_uid_id"] = convert_uuid_to_string(row["data_source_uid_id"])
            return rootdomains_by_org_uid_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


@api_router.post(
    "/crossfeed_vulns",
    dependencies=[Depends(get_api_key)],
    #response_model=schemas.PshttDomainToRunTaskResp,TODO, create schema for generlized output
    tags=["Return all vulnerabilites formatted for crossfeed database."],
)
def crossfeed_vulns(
    data: schemas.GenInputOrgName,
    tokens: dict = Depends(get_api_key)
    ):
    """Returna all vulnerabilities for crossfeed database."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        tasks_dict = {}
        shodan_task = shodan_vulns_task.delay(data.org_acronym)
        tasks_dict['shodan'] = shodan_task.id
        cred_task = credential_breach_vulns_task.delay(data.org_acronym)
        tasks_dict['creds'] = cred_task.id
        was_task = was_vulns_task.delay(data.org_acronym)
        tasks_dict['was'] = was_task.id
        #TODO: add task for XPANSE data
        # Return the new task id w/ "Processing" status
        return {"tasks_dict": tasks_dict, "status": "Processing"}

    else:
        return {"message": "No api key was submitted"}


@api_router.get(
    "/crossfeed_vulns/task/",
    dependencies=[Depends(get_api_key)],
    # , Depends(RateLimiter(times=200, seconds=60))
    # response_model=schemas.PshttDomainToRunTaskResp,
    tags=["Check task status for endpoint crossfeed vulns."],
)
async def crossfeed_vulns_resp(
    scan_name: str, task_id: str, tokens: dict = Depends(get_api_key)
):
    """Retrieve status of a passed task and id."""
    # Retrieve task status
    if scan_name == "shodan":
        task = shodan_vulns_task.AsyncResult(task_id)
    elif scan_name == "creds":
        task = credential_breach_vulns_task.AsyncResult(task_id)
    elif scan_name == "was":
        task = was_vulns_task.AsyncResult(task_id)
    # Return appropriate message for status
    if task.state == "SUCCESS":
        return {"task_id": task_id, "status": "Completed", "result": task.result}
    elif task.state == "PENDING":
        return {"task_id": task_id, "status": "Pending"}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "status": "Failed", "error": str(task.result)}
    else:
        return {"task_id": task_id, "status": task.state}


# --- domain_permu_insert_dnstwist, Issue 706 pe-reports/005 atc-framework ---
@api_router.put(
    "/domain_permu_insert_dnstwist",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert multiple DNSTwist records into the domain_permutations table."],
)
def domain_permu_insert_dnstwist(
    data: schemas.DomainPermuInsertDNSTwistInput, tokens: dict = Depends(get_api_key)
):
    """Insert multiple DNSTwist records into the domain_permutations table through the API."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, proceed
            create_ct = 0
            update_ct = 0
            for record in data.insert_data:
                # convert to dict
                record_dict = dict(record)
                curr_org_inst = Organizations.objects.get(
                    organizations_uid=record_dict["organizations_uid"]
                )
                curr_source_inst = DataSource.objects.get(
                    data_source_uid=record_dict["data_source_uid"]
                )
                curr_subdomain_inst = SubDomains.objects.get(
                    sub_domain_uid=record_dict["sub_domain_uid"]
                )
                # Insert each row of data, on conflict update existing
                try:
                    DomainPermutations.objects.get(
                        organizations_uid=curr_org_inst,
                        domain_permutation=record_dict["domain_permutation"],
                    )
                    # If record already exists, update
                    DomainPermutations.objects.filter(
                        organizations_uid=curr_org_inst,
                        domain_permutation=record_dict["domain_permutation"],
                    ).update(
                        mailicious=record_dict["mailicious"],
                        blocklist_attack_count=record_dict["blocklist_attack_count"],
                        blocklist_report_count=record_dict["blocklist_report_count"],
                        dshield_record_count=record_dict["dshield_record_count"],
                        dshield_attack_count=record_dict["dshield_attack_count"],
                        data_source_uid=record_dict["data_source_uid"],
                        date_active=record_dict["date_active"],
                    )
                    update_ct += 1
                except DomainPermutations.DoesNotExist:
                    # Otherwise, create new record
                    DomainPermutations.objects.create(
                        organizations_uid=curr_org_inst,
                        data_source_uid=curr_source_inst,
                        sub_domain_uid=curr_subdomain_inst,
                        domain_permutation=record_dict["domain_permutation"],
                        ipv4=record_dict["ipv4"],
                        ipv6=record_dict["ipv6"],
                        mail_server=record_dict["mail_server"],
                        name_server=record_dict["name_server"],
                        fuzzer=record_dict["fuzzer"],
                        date_active=record_dict["date_active"],
                        ssdeep_score=record_dict["ssdeep_score"],
                        malicious=record_dict["mailicious"],
                        blocklist_attack_count=record_dict["blocklist_attack_count"],
                        blocklist_report_count=record_dict["blocklist_report_count"],
                        dshield_record_count=record_dict["dshield_record_count"],
                        dshield_attack_count=record_dict["dshield_attack_count"],
                    )
                    create_ct += 1
            return (
                "New DNSTwist data in the domain_permutations table: "
                + str(create_ct)
                + " created, "
                + str(update_ct)
                + " updated"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
    

# --- get_root_domains(), Issue 707 pe-reports/006 atc-framework ---
# This function reuses the /rootdomains_by_org_uid endpoint
    

# --- getDataSource(), Issue 708 pe-reports/007 atc-framework ---
# This function reuses the /data_source_by_name endpoint
    

# --- execute_hibp_breach_values(), Issue 709/008 atc-framework ---
@api_router.put(
    "/cred_breaches_hibp_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert HIBP credential breaches into the credential_breaches table."],
)
def cred_breaches_hibp_insert(
    data: schemas.CredBreachesHIBPInsertInput, tokens: dict = Depends(get_api_key)
):
    """Insert HIBP credential breaches into the credential_breaches table through the API ."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, insert hibp breach data
            insert_count = 0
            update_count = 0
            for row in data.breach_data:
                # Check if record already exists
                row_dict = row.__dict__
                breach_results = CredentialBreaches.objects.filter(
                    breach_name=row_dict["breach_name"]
                )
                if not breach_results.exists():
                    # If not, insert new record
                    curr_data_source_inst = DataSource.objects.get(
                        data_source_uid=row_dict["data_source_uid"]
                    )
                    CredentialBreaches.objects.create(
                        breach_name=row_dict["breach_name"],
                        description=row_dict["description"],
                        exposed_cred_count=row_dict["exposed_cred_count"],
                        breach_date=row_dict["breach_date"],
                        added_date=row_dict["added_date"],
                        modified_date=row_dict["modified_date"],
                        data_classes=row_dict["data_classes"],
                        password_included=row_dict["password_included"],
                        is_verified=row_dict["is_verified"],
                        is_fabricated=row_dict["is_fabricated"],
                        is_sensitive=row_dict["is_sensitive"],
                        is_retired=row_dict["is_retired"],
                        is_spam_list=row_dict["is_spam_list"],
                        data_source_uid=curr_data_source_inst,
                    )
                    insert_count += 1
                else:
                    # Otherwise, update
                    CredentialBreaches.objects.filter(
                        breach_name=row_dict["breach_name"]
                    ).update(
                        modified_daate=row_dict["modified_date"],
                        exposed_cred_count=row_dict["exposed_cred_count"],
                        password_included=row_dict["password_included"]
                    )
                    update_count += 1
            return (
                str(insert_count)
                + " records created, "
                + str(update_count)
                + " records updated in the credential_breaches table"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
    

# --- execute_hibp_emails_values(), Issue 710 pe-reports/009 atc-framework ---
@api_router.put(
    "/cred_exp_hibp_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert HIBP data into the credential_exposures table."],
)
def cred_exp_hibp_insert(
    data: schemas.CredExpHIBPInsertInput, tokens: dict = Depends(get_api_key)
):
    """Insert HIBP data into the credential_exposures table using the API endpoint."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, insert intelx data
            create_cnt = 0
            for row in data.exp_data:
                row_dict = row.__dict__
                try:
                    CredentialExposures.objects.get(
                        breach_name=row_dict["breach_name"],
                        email=row_dict["email"],
                    )
                    # If record already exists, do nothing
                except CredentialExposures.DoesNotExist:
                    # If record doesn't exist yet, create one
                    curr_org_inst = Organizations.objects.get(
                        organizations_uid=row_dict["organizations_uid"]
                    )
                    curr_source_inst = DataSource.objects.get(
                        data_source_uid=row_dict["data_source_uid"]
                    )
                    curr_breach_inst = CredentialBreaches.objects.get(
                        breach_name=row_dict["breach_name"],
                    )
                    CredentialExposures.objects.create(
                        # credential_exposures_uid=uuid.uuid1(),
                        email=row_dict["email"],
                        organizations_uid=curr_org_inst,
                        root_domain=row_dict["root_domain"],
                        sub_domain=row_dict["sub_domain"],
                        modified_date=row_dict["modified_date"],
                        breach_name=row_dict["breach_name"],
                        credential_breaches_uid=curr_breach_inst,
                        data_source_uid=curr_source_inst,
                        name=row_dict["name"],
                    )
                    create_cnt += 1
            # Return success message
            return (
                str(create_cnt)
                + " records created in the credential_exposures table"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
    

# --- get_breach_uids(), Issue 010 atc-framework ---
@api_router.get(
    "/breach_uids",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.BreachUIDs],
    tags=["Retrieve all breach names and uids."],
)
def breach_uids(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get all breach names and uids."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            breach_uids_data = list(
                CredentialBreaches.objects.all().values(
                    "breach_name", 
                    "credential_breaches_uid",
                )
            )
            # Convert data types to match response model
            for row in breach_uids_data:
                row["credential_breaches_uid"] = convert_uuid_to_string(
                    row["credential_breaches_uid"]
                )
            return breach_uids_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
        

# --- query_orgs(), Issue 011 atc-framework ---
@api_router.get(
    "/reported_orgs",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrganizationsFullTable],
    tags=["Retrieve data for all orgs where report_on is true."],
)
def reported_orgs(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get data for all orgs where report_on is true."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            reported_orgs_data = list(
                Organizations.objects.filter(report_on=True).values()
            )
            # Convert data types to match response model
            for row in reported_orgs_data:
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
            return reported_orgs_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}


# --- query_PE_subs(), Issue 012 atc-framework ---
@api_router.post(
    "/subdomains_by_org_uid",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.SubdomainsByOrgUID],
    tags=["Retrieve subdomains for the specified org uid."],
)
def subdomains_by_org_uid(data: schemas.SubdomainsByOrgUIDInput, tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get subdomains for specified org uid."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            subdomains_by_org_uid_data = list(
                RootDomains.objects.filter(
                    organizations_uid=data.org_uid
                ).values(
                    "root_domains_uid__sub_domain", 
                    "root_domain"
                )
            )
            return subdomains_by_org_uid_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
    

# --- insert_shodan_assets(), Issue 016 atc-framework ---
@api_router.put(
    "/shodan_assets_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert Shodan data into the shodan_assets table."],
)
def shodan_assets_insert(
    data: schemas.ShodanAssetsInsertInput, tokens: dict = Depends(get_api_key)
):
    """Insert Shodan data into the shodan_assets table using the API endpoint."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, insert intelx data
            create_cnt = 0
            for row in data.exp_data:
                row_dict = row.__dict__
                try:
                    # Check if record already exists
                    ShodanAssets.objects.get(
                        organizations_uid=row_dict["organizations_uid"], 
                        ip=row_dict["ip"], 
                        port=row_dict["port"], 
                        protocol=row_dict["protocol"], 
                        timestamp=row_dict["timestamp"],
                    )
                    # If record already exists, do nothing
                except CredentialExposures.DoesNotExist:
                    # If record doesn't exist yet, create one
                    curr_org_inst = Organizations.objects.get(
                        organizations_uid=row_dict["organizations_uid"]
                    )
                    ShodanAssets.objects.create(
                        # Need to fill this out
                        # credential_exposures_uid=uuid.uuid1(),
                        email=row_dict["email"],
                        organizations_uid=curr_org_inst,
                        root_domain=row_dict["root_domain"],
                        sub_domain=row_dict["sub_domain"],
                        modified_date=row_dict["modified_date"],
                        breach_name=row_dict["breach_name"],
                        name=row_dict["name"],
                    )
                    create_cnt += 1
            # Return success message
            return (
                str(create_cnt)
                + " records created in the credential_exposures table"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
    

# --- insert_shodan_vulns(), Issue 017 atc-framework ---
@api_router.put(
    "/shodan_vulns_insert",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    tags=["Insert Shodan data into the shodan_vulns table."],
)
def shodan_vulns_insert(
    data: schemas.ShodanVulnsInsertInput, tokens: dict = Depends(get_api_key)
):
    """Insert Shodan data into the shodan_vulns table using the API endpoint."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, insert intelx data
            create_cnt = 0
            for row in data.exp_data:
                row_dict = row.__dict__
                try:
                    CredentialExposures.objects.get(
                        breach_name=row_dict["breach_name"],
                        email=row_dict["email"],
                    )
                    # If record already exists, do nothing
                except CredentialExposures.DoesNotExist:
                    # If record doesn't exist yet, create one
                    curr_org_inst = Organizations.objects.get(
                        organizations_uid=row_dict["organizations_uid"]
                    )
                    curr_source_inst = DataSource.objects.get(
                        data_source_uid=row_dict["data_source_uid"]
                    )
                    curr_breach_inst = CredentialBreaches.objects.get(
                        breach_name=row_dict["breach_name"],
                    )
                    CredentialExposures.objects.create(
                        # credential_exposures_uid=uuid.uuid1(),
                        email=row_dict["email"],
                        organizations_uid=curr_org_inst,
                        root_domain=row_dict["root_domain"],
                        sub_domain=row_dict["sub_domain"],
                        modified_date=row_dict["modified_date"],
                        breach_name=row_dict["breach_name"],
                        credential_breaches_uid=curr_breach_inst,
                        data_source_uid=curr_source_inst,
                        name=row_dict["name"],
                    )
                    create_cnt += 1
            # Return success message
            return (
                str(create_cnt)
                + " records created in the credential_exposures table"
            )
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}
    

# --- get_demo_orgs(), Issue 018 atc-framework ---
@api_router.get(
    "/organizations_demo",
    dependencies=[
        Depends(get_api_key)
    ],  # Depends(RateLimiter(times=200, seconds=60))],
    response_model=List[schemas.OrganizationsFullTable],
    tags=["Retrieve data for all demo orgs."],
)
def organizations_demo(tokens: dict = Depends(get_api_key)):
    """Call API endpoint to get data for all demo orgs."""
    # Check for API key
    LOGGER.info(f"The api key submitted {tokens}")
    if tokens:
        try:
            userapiTokenverify(theapiKey=tokens)
            # If API key valid, make query
            organizations_demo_data = list(
                Organizations.objects.filter(demo=True).values()
            )
            # Convert data types to match response model
            for row in organizations_demo_data:
                row["organizations_uid"] = convert_uuid_to_string(
                    row["organizations_uid"]
                )
            return organizations_demo_data
        except ObjectDoesNotExist:
            LOGGER.info("API key expired please try again")
    else:
        return {"message": "No api key was submitted"}