"""Pydantic models used by FastAPI."""
# Standard Python Libraries
from datetime import date, datetime
from decimal import Decimal

# from pydantic.types import UUID1, UUID
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

# Third-Party Libraries
from pydantic import BaseModel, EmailStr, Field

"""
Developer Note: If there comes an instance as in class Cidrs where there are
foreign keys. The data type will not be what is stated in the database. What is
happening is the data base is making a query back to the foreign key table and
returning it as the column in its entirety i.e. select * from <table>, so it
will error and not be able to report on its data type. In these scenario's use
the data type "Any" to see what the return is.
"""


class OrgType(BaseModel):
    """OrgType schema."""

    org_type_uid: UUID

    class Config:
        """OrgType schema configuration."""

        orm_mode = True


class OrganizationBase(BaseModel):
    """OrganizationBase schema."""

    organizations_uid: UUID
    name: str
    cyhy_db_name: Optional[str] = None
    org_type_uid: Any
    report_on: bool
    password: Optional[str]
    date_first_reported: Optional[datetime]
    parent_org_uid: Any
    premium_report: Optional[bool] = None
    agency_type: Optional[str] = None
    demo: bool = False

    class Config:
        """OrganizationBase schema configuration."""

        orm_mode = True
        validate_assignment = True


class Organization(OrganizationBase):
    """Organization schema."""

    pass

    class Config:
        """Organization schema configuration."""

        orm_mode = True


class SubDomainBase(BaseModel):
    """SubDomainBase schema."""

    sub_domain_uid: UUID
    sub_domain: str
    root_domain_uid: Optional[Any]
    data_source_uid: Optional[Any]
    dns_record_uid: Optional[Any] = None
    status: bool = False

    class Config:
        """SubDomainBase schema configuration."""

        orm_mode = True
        validate_assignment = True


class VwBreachcomp(BaseModel):
    """VwBreachcomp schema."""

    credential_exposures_uid: str
    email: str
    breach_name: str
    organizations_uid: str
    root_domain: str
    sub_domain: str
    hash_type: str
    name: str
    login_id: str
    password: str
    phone: str
    data_source_uid: str
    description: str
    breach_date: str
    added_date: str
    modified_date: str
    data_classes: str
    password_included: str
    is_verified: str
    is_fabricated: str
    is_sensitive: str
    is_retired: str
    is_spam_list: str


class VwBreachDetails(BaseModel):
    """VwBreachDetails schema class."""

    organizations_uid: Optional[str] = None
    breach_name: Optional[str] = None
    mod_date: Optional[str] = None
    description: Optional[str] = None
    breach_date: Optional[str] = None
    password_included: Optional[bool] = None
    number_of_creds: Optional[int] = None

    class Config:
        """VwBreachDetails schema config class."""

        orm_mode = True


class VwBreachDetailsTaskResp(BaseModel):
    """VwBreachDetailsTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwBreachDetails]] = None
    error: Optional[str] = None


class VwCredsbydate(BaseModel):
    """VwCredsbydate schema."""

    organizations_uid: Optional[str] = None
    mod_date: Optional[str] = None
    no_password: Optional[int] = None
    password_included: Optional[int] = None


class VwCredsbydateTaskResp(BaseModel):
    """VwCredsbydateTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwCredsbydate]] = None
    error: Optional[str] = None


class VwOrgsAttacksurface(BaseModel):
    """VwOrgsAttacksurface schema."""

    organizations_uid: UUID
    cyhy_db_name: str
    num_ports: str
    num_root_domain: str
    num_sub_domain: str
    num_ips: str

    class Config:
        """VwOrgsAttacksurface schema configuration."""

        orm_mode = True


class VwOrgsAttacksurfaceInput(BaseModel):
    """VwOrgsAttacksurfaceInput schema."""

    organizations_uid: UUID

    class Config:
        """VwOrgsAttacksurfaceInput schema configuration."""

        orm_mode = True


class MatVwOrgsAllIps(BaseModel):
    """MatVwOrgsAllIps schema."""

    organizations_uid: Any
    cyhy_db_name: str
    ip_addresses: List[Optional[str]] = []

    class Config:
        """MatVwOrgsAllIps schema configuration."""

        orm_mode = True


class TaskResponse(BaseModel):
    """TaskResponse schema."""

    task_id: str
    status: str
    result: Optional[List[MatVwOrgsAllIps]] = None
    error: Optional[str] = None


class veMatVwOrgsAllIps(BaseModel):
    """veMatVwOrgsAllIps schema."""

    cyhy_db_name: Optional[str]

    class Config:
        """veMatVwOrgsAllIps schema configuration."""

        orm_mode = True


class veTaskResponse(BaseModel):
    """veTaskResponse schema."""

    task_id: str
    status: str
    result: Optional[List[veMatVwOrgsAllIps]] = None
    error: Optional[str] = None


class WASDataBase(BaseModel):
    """WASDataBase schema."""

    # customer_id: UUID
    tag: Optional[str] = "test"
    customer_name: Optional[str] = "test"
    testing_sector: Optional[str] = "test"
    ci_type: Optional[str] = "test"
    jira_ticket: Optional[str] = "test"
    ticket: Optional[str] = "test"
    next_scheduled: Optional[str] = "test"
    last_scanned: Optional[str] = "test"
    frequency: Optional[str] = "test"
    comments_notes: Optional[str] = "test"
    was_report_poc: Optional[str] = "test"
    was_report_email: Optional[str] = "test"
    onboarding_date: Optional[str] = "test"
    no_of_web_apps: Optional[int]
    no_web_apps_last_updated: Optional[str] = "test"
    elections: Optional[str] = "test"
    fceb: Optional[str] = "test"
    special_report: Optional[str] = "test"
    report_password: Optional[str] = "test"
    child_tags: Optional[str] = "test"

    class Config:
        """WASDataBase schema configuration."""

        orm_mode = True
        validate_assignment = True


class WeeklyStatuses(BaseModel):
    """WeeklyStatuses schema."""

    key_accomplishments: Optional[str] = None
    ongoing_task: Optional[str] = None
    upcoming_task: Optional[str] = None
    obstacles: Optional[str] = None
    non_standard_meeting: Optional[str] = None
    deliverables: Optional[str] = None
    pto: Optional[str] = None
    week_ending: Optional[str] = None
    notes: Optional[str] = None
    statusComplete: Optional[str] = None

    class Config:
        """WeeklyStatuses schema configuration."""

        orm_mode = True
        validate_assignment = True


class UserStatuses(BaseModel):
    """UserStatuses schema."""

    user_fname: str

    class Config:
        """UserStatuses schema configuration."""

        orm_mode = True
        validate_assignment = True


class CyhyPortScans(BaseModel):
    """CyhyPortScans schema."""

    cyhy_port_scans_uid: UUID
    organizations_uid: Any
    cyhy_id: str
    cyhy_time: str
    service_name: str
    port: str
    product: str
    cpe: str
    first_seen: str
    last_seen: str
    ip: str
    state: str
    agency_type: str

    class Config:
        """CyhyPortScans schema configuration."""

        orm_mode = True
        validate_assignment = True


class CyhyDbAssets(BaseModel):
    """CyhyDbAssets schema."""

    # field_id: str
    org_id: str
    org_name: str
    contact: Optional[str] = None
    network: str
    type: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    currently_in_cyhy: Optional[str] = None

    class Config:
        """CyhyDbAssets schema configuration."""

        orm_mode = True


class CyhyDbAssetsInput(BaseModel):
    """CyhyDbAssetsInput schema."""

    org_id: str

    class Config:
        """CyhyDbAssetsInput schema configuration."""

        orm_mode = True


class Cidrs(BaseModel):
    """Cidrs schema."""

    cidr_uid: UUID
    network: Any
    organizations_uid: Any
    data_source_uid: Any
    insert_alert: Optional[str] = None

    class Config:
        """Cidrs schema configuration."""

        orm_mode = True


class VwCidrs(BaseModel):
    """VwCidrs schema."""

    cidr_uid: str
    network: str
    organizations_uid: str
    data_source_uid: str
    insert_alert: Optional[str] = None


class DataSource(BaseModel):
    """DataSource schema."""

    data_source_uid: Optional[UUID]
    name: Optional[str]
    description: Optional[str]
    last_run: Optional[str]

    class Config:
        """DataSource schema configuration."""

        orm_mode = True


class UserAPIBase(BaseModel):
    """UserAPIBase schema."""

    # user_id: int
    refresh_token: str


class UserAPI(UserAPIBase):
    """UserAPI schema."""

    pass

    class Config:
        """UserAPI schema configuration."""

        orm_mode = True


class TokenSchema(BaseModel):
    """TokenSchema schema."""

    access_token: str
    refresh_token: str


class TokenPayload(BaseModel):
    """TokenPayload schema."""

    sub: Optional[str] = None
    exp: Optional[int] = None


class UserAuth(BaseModel):
    """UserAuth schema."""

    # id: UUID = Field(..., description='user UUID')
    # email: EmailStr = Field(..., description="user email")
    username: str = Field(..., description="user name")
    # password: str = Field(..., min_length=5, max_length=24,
    #                       description="user password")


class UserOut(BaseModel):
    """UserOut schema."""

    id: UUID
    email: str


class SystemUser(UserOut):
    """SystemUser schema."""

    password: str


# Shared properties
class UserBase(BaseModel):
    """UserBase schema."""

    email: Optional[EmailStr] = None
    is_active: Optional[bool] = True
    is_superuser: bool = False
    full_name: Optional[str] = None


# Properties to receive via API on creation
class UserCreate(UserBase):
    """UserCreate schema."""

    email: EmailStr
    password: str


# Properties to receive via API on update
class UserUpdate(UserBase):
    """UserUpdate schema."""

    password: Optional[str] = None


class UserInDBBase(UserBase):
    """UserInDBBase schema."""

    id: Optional[int] = None

    class Config:
        """UserInDBBase schema configuration."""

        orm_mode = True


# Additional properties to return via API
class User(UserInDBBase):
    """User schema."""

    pass


# Additional properties stored in DB
class UserInDB(UserInDBBase):
    """UserInDB schema."""

    hashed_password: str


# ---------- Generalized Schemas ----------
# Generalized 1 org_uid input schema
class GenInputOrgUIDSingle(BaseModel):
    """GenInputOrgUIDSingle schema class."""

    org_uid: str

    class Config:
        """GenInputOrgUIDSingle schema config class."""

        orm_mode = True


# Generalized 1 org cyhy_db_name input schema
class GenInputOrgCyhyNameSingle(BaseModel):
    """GenInputOrgCyhyNameSingle schema class."""

    org_cyhy_name: str

    class Config:
        """GenInputOrgCyhyNameSingle schema config class."""

        orm_mode = True


# Generalized 1 org_uid, 1 date input schema
class GenInputOrgUIDDateSingle(BaseModel):
    """GenInputOrgUIDDateSingle schema class."""

    org_uid: str
    date: str

    class Config:
        """GenInputOrgUIDDateSingle schema config class."""

        orm_mode = True


# Generalized list of org_uids input schema
class GenInputOrgUIDList(BaseModel):
    """GenInputOrgUIDList schema class."""

    org_uid_list: List[str]

    class Config:
        """GenInputOrgUIDList schema config class."""

        orm_mode = True


class GenInputOrgUIDDateRange(BaseModel):
    """GenInputOrgUIDDateRange schema class."""

    org_uid: str
    start_date: str
    end_date: str

    class Config:
        """GenInputOrgUIDDateRange schema config class."""


# Generalized start/end date input schema
class GenInputDateRange(BaseModel):
    """GenInputDateRange schema class."""

    start_date: str
    end_date: str

    class Config:
        """GenInputDateRange schema config class."""

        orm_mode = True


# Generalized list of org_uids and start/end date input schema
class GenInputOrgUIDListDateRange(BaseModel):
    """GenInputOrgUIDListDateRange schema class."""

    org_uid_list: List[str]
    start_date: str
    end_date: str

    class Config:
        """GenInputOrgUIDListDateRange schema config class."""

        orm_mode = True


# ---------- I-Score View Schemas, Issue 570 ----------
# vw_iscore_vs_vuln schema:
class VwIscoreVSVuln(BaseModel):
    """VwIscoreVSVuln schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None

    class Config:
        """VwIscoreVSVuln schema config class."""

        orm_mode = True


# vw_iscore_vs_vuln input schema:
class VwIscoreVSVulnInput(BaseModel):
    """VwIscoreVSVulnInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwIscoreVSVulnInput schema config class."""

        orm_mode = True


# vw_iscore_vs_vuln task response schema:
class VwIscoreVSVulnTaskResp(BaseModel):
    """VwIscoreVSVulnTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreVSVuln]] = None
    error: Optional[str] = None


# vw_iscore_vs_vuln_prev schema:
class VwIscoreVSVulnPrev(BaseModel):
    """VwIscoreVSVulnPrev schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None
    time_closed: Optional[str] = None

    class Config:
        """VwIscoreVSVulnPrev schema config class."""

        orm_mode = True


# vw_iscore_vs_vuln_prev input schema:
class VwIscoreVSVulnPrevInput(BaseModel):
    """VwIscoreVSVulnPrevInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscoreVSVulnPrevInput schema config class."""

        orm_mode = True


# vw_iscore_vs_vuln_prev task response schema:
class VwIscoreVSVulnPrevTaskResp(BaseModel):
    """VwIscoreVSVulnPrevTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreVSVulnPrev]] = None
    error: Optional[str] = None


# vw_iscore_pe_vuln schema:
class VwIscorePEVuln(BaseModel):
    """VwIscorePEVuln schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None

    class Config:
        """VwIscorePEVuln schema config class."""

        orm_mode = True


# vw_iscore_pe_vuln input schema:
class VwIscorePEVulnInput(BaseModel):
    """VwIscorePEVulnInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscorePEVulnInput schema config class."""

        orm_mode = True


# vw_iscore_pe_vuln task response schema:
class VwIscorePEVulnTaskResp(BaseModel):
    """VwIscorePEVulnTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePEVuln]] = None
    error: Optional[str] = None


# vw_iscore_pe_cred schema:
class VwIscorePECred(BaseModel):
    """VwIscorePECred schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    password_creds: Optional[int] = None
    total_creds: Optional[int] = None

    class Config:
        """VwIscorePECred schema config class."""

        orm_mode = True


# vw_iscore_pe_cred input schema:
class VwIscorePECredInput(BaseModel):
    """VwIscorePECredInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscorePECredInput schema config class."""

        orm_mode = True


# vw_iscore_pe_cred task response schema:
class VwIscorePECredTaskResp(BaseModel):
    """VwIscorePECredTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePECred]] = None
    error: Optional[str] = None


# vw_iscore_pe_breach schema:
class VwIscorePEBreach(BaseModel):
    """VwIscorePEBreach schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    breach_count: Optional[int] = None

    class Config:
        """VwIscorePEBreach schema config class."""

        orm_mode = True


# vw_iscore_pe_breach input schema:
class VwIscorePEBreachInput(BaseModel):
    """VwIscorePEBreachInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscorePEBreachInput schema config class."""

        orm_mode = True


# vw_iscore_pe_breach task response schema:
class VwIscorePEBreachTaskResp(BaseModel):
    """VwIscorePEBreachTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePEBreach]] = None
    error: Optional[str] = None


# vw_iscore_pe_darkweb schema:
class VwIscorePEDarkweb(BaseModel):
    """VwIscorePEDarkweb schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    alert_type: Optional[str] = None
    date: Optional[str] = None
    Count: Optional[int] = None

    class Config:
        """VwIscorePEDarkweb schema config class."""

        orm_mode = True


# vw_iscore_pe_darkweb input schema:
class VwIscorePEDarkwebInput(BaseModel):
    """VwIscorePEDarkwebInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str
    # Don't forget 0001-01-01 dates

    class Config:
        """VwIscorePEDarkwebInput schema config class."""

        orm_mode = True


# vw_iscore_pe_darkweb task response schema:
class VwIscorePEDarkwebTaskResp(BaseModel):
    """VwIscorePEDarkwebTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePEDarkweb]] = None
    error: Optional[str] = None


# vw_iscore_pe_protocol schema:
class VwIscorePEProtocol(BaseModel):
    """VwIscorePEProtocol schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    port: Optional[str] = None
    ip: Optional[str] = None
    protocol: Optional[str] = None
    protocol_type: Optional[str] = None
    date: Optional[str] = None

    class Config:
        """VwIscorePEProtocol schema config class."""

        orm_mode = True


# vw_iscore_pe_protocol input schema:
class VwIscorePEProtocolInput(BaseModel):
    """VwIscorePEProtocolInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscorePEProtocolInput schema config class."""

        orm_mode = True


# vw_iscore_pe_protocol task response schema:
class VwIscorePEProtocolTaskResp(BaseModel):
    """VwIscorePEProtocolTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscorePEProtocol]] = None
    error: Optional[str] = None


# vw_iscore_was_vuln schema:
class VwIscoreWASVuln(BaseModel):
    """VwIscoreWASVuln schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    date: Optional[str] = None
    cve_name: Optional[str] = None
    cvss_score: Optional[float] = None
    owasp_category: Optional[str] = None

    class Config:
        """VwIscoreWASVuln schema config class."""

        orm_mode = True


# vw_iscore_was_vuln input schema:
class VwIscoreWASVulnInput(BaseModel):
    """VwIscoreWASVulnInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscoreWASVulnInput schema config class."""

        orm_mode = True


# vw_iscore_was_vuln task response schema:
class VwIscoreWASVulnTaskResp(BaseModel):
    """VwIscoreWASVulnTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreWASVuln]] = None
    error: Optional[str] = None


# vw_iscore_was_vuln_prev schema:
class VwIscoreWASVulnPrev(BaseModel):
    """VwIscoreWASVulnPrev schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    was_total_vulns_prev: Optional[int] = None
    date: Optional[str] = None

    class Config:
        """VwIscoreWASVulnPrev schema config class."""

        orm_mode = True


# vw_iscore_was_vuln_prev input schema:
class VwIscoreWASVulnPrevInput(BaseModel):
    """VwIscoreWASVulnPrevInput schema class."""

    specified_orgs: List[str]
    start_date: str
    end_date: str

    class Config:
        """VwIscoreWASVulnPrevInput schema config class."""

        orm_mode = True


# vw_iscore_was_vuln_prev task response schema:
class VwIscoreWASVulnPrevTaskResp(BaseModel):
    """VwIscoreWASVulnPrevTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreWASVulnPrev]] = None
    error: Optional[str] = None


# KEV list query schema (no view):
# KEV list query does not use any input parameters
class KEVList(BaseModel):
    """KEVList schema class."""

    kev: str

    class Config:
        """KEVList schema config class."""

        orm_mode = True


# KEV list query task response schema (no view):
class KEVListTaskResp(BaseModel):
    """KEVListTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[KEVList]] = None
    error: Optional[str] = None


# ---------- D-Score View Schemas, Issue 571 ----------
# vw_dscore_vs_cert schema:
class VwDscoreVSCert(BaseModel):
    """VwDscoreVSCert schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_cert: Optional[int] = None
    num_monitor_cert: Optional[int] = None

    class Config:
        """VwDscoreVSCert schema config class."""

        orm_mode = True


# vw_dscore_vs_cert input schema:
class VwDscoreVSCertInput(BaseModel):
    """VwDscoreVSCertInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscoreVSCertInput schema config class."""

        orm_mode = True


# vw_dscore_vs_cert task response schema:
class VwDscoreVSCertTaskResp(BaseModel):
    """VwDscoreVSCertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscoreVSCert]] = None
    error: Optional[str] = None


# vw_dscore_vs_mail schema:
class VwDscoreVSMail(BaseModel):
    """VwDscoreVSMail schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_valid_dmarc: Optional[int] = None
    num_valid_spf: Optional[int] = None
    num_valid_dmarc_or_spf: Optional[int] = None
    total_mail_domains: Optional[int] = None

    class Config:
        """VwDscoreVSMail schema config class."""

        orm_mode = True


# vw_dscore_vs_mail input schema:
class VwDscoreVSMailInput(BaseModel):
    """VwDscoreVSMailInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscoreVSMailInput schema config class."""

        orm_mode = True


# vw_dscore_vs_mail task response schema:
class VwDscoreVSMailTaskResp(BaseModel):
    """VwDscoreVSMailTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscoreVSMail]] = None
    error: Optional[str] = None


# vw_dscore_pe_ip schema:
class VwDscorePEIp(BaseModel):
    """VwDscorePEIp schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_ip: Optional[int] = None
    num_monitor_ip: Optional[int] = None

    class Config:
        """VwDscorePEIp schema config class."""

        orm_mode = True


# vw_dscore_pe_ip input schema:
class VwDscorePEIpInput(BaseModel):
    """VwDscorePEIpInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscorePEIpInput schema config class."""

        orm_mode = True


# vw_dscore_pe_ip task response schema:
class VwDscorePEIpTaskResp(BaseModel):
    """VwDscorePEIpTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscorePEIp]] = None
    error: Optional[str] = None


# vw_dscore_pe_domain schema:
class VwDscorePEDomain(BaseModel):
    """VwDscorePEDomain schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_domain: Optional[int] = None
    num_monitor_domain: Optional[int] = None

    class Config:
        """VwDscorePEDomain schema config class."""

        orm_mode = True


# vw_dscore_pe_domain input schema:
class VwDscorePEDomainInput(BaseModel):
    """VwDscorePEDomainInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscorePEDomainInput schema config class."""

        orm_mode = True


# vw_dscore_pe_domain task response schema:
class VwDscorePEDomainTaskResp(BaseModel):
    """VwDscorePEDomainTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscorePEDomain]] = None
    error: Optional[str] = None


# vw_dscore_was_webapp schema:
class VwDscoreWASWebapp(BaseModel):
    """VwDscoreWASWebapp schema class."""

    organizations_uid: str
    parent_org_uid: Optional[str] = None
    num_ident_webapp: Optional[int] = None
    num_monitor_webapp: Optional[int] = None

    class Config:
        """VwDscoreWASWebapp schema config class."""

        orm_mode = True


# vw_dscore_was_webapp input schema:
class VwDscoreWASWebappInput(BaseModel):
    """VwDscoreWASWebappInput schema class."""

    specified_orgs: List[str]

    class Config:
        """VwDscoreWASWebappInput schema config class."""

        orm_mode = True


# vw_dscore_was_webapp task response schema:
class VwDscoreWASWebappTaskResp(BaseModel):
    """VwDscoreWASWebappTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwDscoreWASWebapp]] = None
    error: Optional[str] = None


# FCEB status query schema (no view):
class FCEBStatus(BaseModel):
    """FCEBStatus schema class."""

    organizations_uid: str
    fceb: Optional[bool] = None

    class Config:
        """FCEBStatus schema config class."""

        orm_mode = True


# FCEB status query input schema (no view):
class FCEBStatusInput(BaseModel):
    """FCEBStatusInput schema class."""

    specified_orgs: List[str]

    class Config:
        """FCEBStatusInput schema config class."""

        orm_mode = True


# FCEB status query task response schema (no view):
class FCEBStatusTaskResp(BaseModel):
    """FCEBStatusTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[FCEBStatus]] = None
    error: Optional[str] = None


# ---------- Misc. Score Schemas ----------
# vw_iscore_orgs_ip_counts schema:
# vw_iscore_orgs_ip_counts does not use any input parameters
class VwIscoreOrgsIpCounts(BaseModel):
    """VwIscoreOrgsIpCounts schema class."""

    organizations_uid: str
    cyhy_db_name: str

    class Config:
        """VwIscoreOrgsIpCounts schema config class."""

        orm_mode = True


# vw_iscore_orgs_ip_counts task response schema:
class VwIscoreOrgsIpCountsTaskResp(BaseModel):
    """VwIscoreOrgsIpCountsTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[VwIscoreOrgsIpCounts]] = None
    error: Optional[str] = None


# --- execute_ips(), Issue 559 ---
# Insert record into Ips
class IpsInsert(BaseModel):
    """IpsInsert schema class."""

    ip_hash: str
    ip: str
    origin_cidr: str

    class Config:
        """IpsInsert schema config class."""

        orm_mode = True


# --- execute_ips(), Issue 559 ---
# Insert record into Ips, input
class IpsInsertInput(BaseModel):
    """IpsInsertInput schema class."""

    new_ips: List[IpsInsert]

    class Config:
        """IpsInsertInput schema config class."""

        orm_mode = True


# --- execute_ips(), Issue 559 ---
# Insert record into Ips, task resp
class IpsInsertTaskResp(BaseModel):
    """IpsInsertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[str] = None
    error: Optional[str] = None


# --- query_all_subs()/query_subs(), Issue 560, 633 ---
# Get entire sub_domains table, single output
class SubDomainTable(BaseModel):
    """SubDomainTable schema class."""

    sub_domain_uid: Optional[str] = None
    sub_domain: Optional[str] = None
    root_domain_uid_id: Optional[str] = None
    data_source_uid_id: Optional[str] = None
    dns_record_uid_id: Optional[str] = None
    status: Optional[bool] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    current: Optional[bool] = None
    identified: Optional[bool] = None

    class Config:
        """SubDomainTable schema config class."""

        orm_mode = True
        validate_assignment = True


# --- query_all_subs()/query_subs(), Issue 560, 633 ---
# Get entire sub_domains table, paged output
class SubDomainPagedResult(BaseModel):
    """SubDomainPagedResult schema class."""

    total_pages: int
    current_page: int
    data: List[SubDomainTable]


# --- query_all_subs(), Issue 633 ---
# Get entire sub_domains table, paged input
class SubDomainPagedInput(BaseModel):
    """SubDomainPagedInput schema class."""

    org_uid: str
    page: int
    per_page: int

    class Config:
        """SubDomainPagedInput schema config class."""

        orm_mode = True


# --- query_all_subs()/query_subs, Issue 560, 633 ---
# Get entire sub_domains table, paged task resp
class SubDomainPagedTaskResp(BaseModel):
    """SubDomainPagedTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[SubDomainPagedResult] = None
    error: Optional[str] = None


# --- query_domMasq_alerts(), Issue 562
# Return all the fields of the domain_alerts table
class DomainAlertsTable(BaseModel):
    """DomainAlertsTable schema class."""

    domain_alert_uid: str
    sub_domain_uid_id: Optional[str] = None
    data_source_uid_id: Optional[str] = None
    organizations_uid: Optional[str] = None
    alert_type: Optional[str] = None
    message: Optional[str] = None
    previous_value: Optional[str] = None
    new_value: Optional[str] = None
    date: Optional[str] = None

    class Config:
        """DomainAlertsTable schema config class."""

        orm_mode = True


# --- query_domMasq(), Issue 563
# Return all the fields of the domain_permutation table
class DomainPermuTable(BaseModel):
    """DomainPermuTable schema class."""

    suspected_domain_uid: str
    organizations_uid_id: str
    domain_permutation: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    mail_server: Optional[str] = None
    name_server: Optional[str] = None
    fuzzer: Optional[str] = None
    date_observed: Optional[str] = None
    ssdeep_score: Optional[str] = None
    malicious: Optional[bool] = None
    blocklist_attack_count: Optional[int] = None
    blocklist_report_count: Optional[int] = None
    data_source_uid_id: Optional[str] = None
    sub_domain_uid_id: Optional[str] = None
    dshield_record_count: Optional[int] = None
    date_active: Optional[str] = None

    class Config:
        """DomainPermuTable schema config class."""

        orm_mode = True


# --- insert_roots(), Issue 564
# Return all the fields of the domain_permutation table
class OrganizationsTable(BaseModel):
    """OrganizationsTable schema class."""

    organizations_uid: Optional[str] = None
    name: Optional[str] = None
    cyhy_db_name: Optional[str] = None
    org_type_uid_id: Optional[str] = None
    report_on: Optional[bool] = None
    # password: Optional[str] = None
    date_first_reported: Optional[str] = None
    parent_org_uid_id: Optional[str] = None
    premium_report: Optional[bool] = None
    agency_type: Optional[str] = None
    demo: Optional[bool] = None
    scorecard: Optional[bool] = None
    fceb: Optional[bool] = None
    receives_cyhy_report: Optional[bool] = None
    receives_bod_report: Optional[bool] = None
    receives_cybex_report: Optional[bool] = None
    run_scans: Optional[bool] = None
    is_parent: Optional[bool] = None
    ignore_roll_up: Optional[bool] = None
    retired: Optional[bool] = None
    cyhy_period_start: Optional[str] = None
    fceb_child: Optional[bool] = None
    election: Optional[bool] = None
    scorecard_child: Optional[bool] = None

    class Config:
        """OrganizationsTable schema config class."""

        orm_mode = True


# --- insert_roots(), Issue 564
# Return all the fields of the domain_permutation table, input
class RootDomainsInsertInput(BaseModel):
    """RootDomainsInsertInput schema class."""

    org_dict: OrganizationsTable
    domain_list: list[str]

    class Config:
        """RootDomainsInsertInput schema config class."""

        orm_mode = True


# --- get_orgs_contacts(), Issue 601
# Get the contact info for all orgs where report_on is true
class OrgsReportOnContacts(BaseModel):
    """OrgsReportOnContacts schema class."""

    email: str
    contact_type: str
    org_id: str

    class Config:
        """OrgsReportOnContacts schema config class."""

        orm_mode = True


# --- get_org_assets_count_past(), Issue 603 ---
# Generalized schema for returning all report_summary_stats table fields
class RSSTable(BaseModel):
    """RSSTable schema class."""

    report_uid: Optional[str]
    organizations_uid_id: Optional[str]
    start_date: Optional[str]
    end_date: Optional[str]
    ip_count: Optional[int]
    root_count: Optional[int]
    sub_count: Optional[int]
    ports_count: Optional[int]
    creds_count: Optional[int]
    breach_count: Optional[int]
    creds_password_count: Optional[int]
    domain_alert_count: Optional[int]
    suspected_domain_count: Optional[int]
    insecure_port_count: Optional[int]
    verified_vuln_count: Optional[int]
    suspected_vuln_count: Optional[int]
    threat_actor_count: Optional[int]
    dark_web_alerts_count: Optional[int]
    dark_web_mentions_count: Optional[int]
    dark_web_executive_alerts_count: Optional[int]
    dark_web_asset_alerts_count: Optional[int]
    pe_number_score: Optional[str]  # ?
    pe_letter_grade: Optional[str]
    pe_percent_score: Optional[float]  # ?
    cidr_count: Optional[int]
    port_protocol_count: Optional[int]
    software_count: Optional[int]
    foreign_ips_count: Optional[int]

    class Config:
        """RSSTable schema config class."""

        orm_mode = True


# --- get_org_assets_count(), Issue 604 ---
# Get asset counts for the specified org_uid
class AssetCountsByOrg(BaseModel):
    """AssetCountsByOrg schema class."""

    organizations_uid: str
    cyhy_db_name: str
    num_root_domain: int
    num_sub_domain: int
    num_ips: int
    num_ports: int
    num_cidrs: int
    num_ports_protocols: int
    num_software: int
    num_foreign_ips: int

    class Config:
        """AssetCountsByOrg schema config class."""

        orm_mode = True


# --- get_new_orgs(), Issue 605, 606, 607 ---
# Generalized schema for returning all organizations table fields
class OrgsTable(BaseModel):
    """OrgsTable schema class."""

    organizations_uid: str
    name: Optional[str] = None
    cyhy_db_name: Optional[str] = None
    org_type_uid_id: Optional[str] = None
    report_on: Optional[bool] = None
    password: Optional[str] = None
    date_first_reported: Optional[str] = None
    parent_org_uid_id: Optional[str] = None
    premium_report: Optional[bool] = None
    agency_type: Optional[str] = None
    demo: Optional[bool] = None
    scorecard: Optional[bool] = None
    fceb: Optional[bool] = None
    receives_cyhy_report: Optional[bool] = None
    receives_bod_report: Optional[bool] = None
    receives_cybex_report: Optional[bool] = None
    run_scans: Optional[bool] = None
    is_parent: Optional[bool] = None
    ignore_roll_up: Optional[bool] = None
    retired: Optional[bool] = None
    cyhy_period_start: Optional[str] = None
    fceb_child: Optional[bool] = None
    election: Optional[bool] = None
    scorecard_child: Optional[bool] = None

    class Config:
        """OrgsTable schema config class."""

        orm_mode = True


# --- set_org_to_report_on(), Issue 606, 607 ---
# Set specified organization to report_on
class OrgsSetReportOnInput(BaseModel):
    """OrgsSetReportOnInput schema class."""

    cyhy_db_name: str
    premium: bool

    class Config:
        """OrgsSetReportOnInput schema config class."""


# --- query_cyhy_assets(), Issue 608 ---
# Get CyHy database assets for an org (cyhy_db_name)
class CyhyDbAssetsByOrg(BaseModel):
    """CyhyDbAssetsByOrg schema class."""

    field_id: Optional[str] = None
    org_id: Optional[str] = None
    org_name: Optional[str] = None
    contact: Optional[str] = None
    network: Optional[str] = None
    type: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    currently_in_cyhy: Optional[bool] = None

    class Config:
        """CyhyDbAssetsByOrg schema config class."""

        orm_mode = True


# --- get_cidrs_and_ips(), Issue 610 ---
# Get CIDRs and IPs data for an org
class CidrsIpsByOrg(BaseModel):
    """CidrsIpsByOrg schema class."""

    ip: str

    class Config:
        """CidrsIpsByOrg schema config class."""

        orm_mode = True


# --- query_ips(), Issue 611 ---
# Get IPs data for an org
class IpsByOrg(BaseModel):
    """IpsByOrg schema class."""

    cidr_ip_data: List[CidrsIpsByOrg]
    sub_root_ip_data: List[CidrsIpsByOrg]

    class Config:
        """IpsByOrg schema config class."""

        orm_mode = True


# --- query_extra_ips(), Issue 612 ---
# Get "extra" IP data for an org
class ExtraIpsByOrg(BaseModel):
    """ExtraIpsByOrg schema class."""

    ip_hash: str
    ip: str

    class Config:
        """ExtraIpsByOrg schema config class."""

        orm_mode = True


# --- set_from_cidr(), Issue 616 ---
# Set from_cidr to True for any IPs that have an origin_cidr, task resp
class IpsUpdateFromCidrTaskResp(BaseModel):
    """IpsUpdateFromCidrTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[str] = None
    error: Optional[str] = None


# --- query_cidrs_by_org(), Issue 618 ---
# Get all CIDRs for specified org
class CidrsByOrg(BaseModel):
    """CidrsByOrg schema class."""

    cidr_uid: Optional[str] = None
    network: Optional[str] = None
    organizations_uid_id: Optional[str] = None
    data_source_uid_id: Optional[str] = None
    insert_alert: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    current: Optional[bool] = None

    class Config:
        """CidrsByOrg schema config class."""

        orm_mode = True


# --- query_ports_protocols(), Issue 619 ---
# Get distinct ports/protocols for specified org
class PortsProtocolsByOrg(BaseModel):
    """PortsProtocolsByOrg schema class."""

    port: Optional[int] = None
    protocol: Optional[str] = None

    class Config:
        """PortsProtocolsByOrg schema config class."""

        orm_mode = True


# --- query_software(), Issue 620 ---
# Get distinct software for specified org
class SoftwareByOrg(BaseModel):
    """SoftwareByOrg schema class."""

    product: Optional[str] = None

    class Config:
        """SoftwareByOrg schema config class."""

        orm_mode = True


# --- query_foreign_ips(), Issue 621 ---
# Get assets outside the US for specified org
class ForeignIpsByOrg(BaseModel):
    """ForeignIpsByOrg schema class."""

    shodan_asset_uid: Optional[str] = None
    organizations_uid_id: Optional[str] = None
    organization: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    timestamp: Optional[str] = None
    product: Optional[str] = None
    server: Optional[str] = None
    tags: Optional[List[str]] = None  # List
    domains: Optional[List[str]] = None  # List
    hostnames: Optional[List[str]] = None  # List
    isn: Optional[str] = None
    asn: Optional[int] = None
    data_source_uid_id: Optional[str] = None
    country_code: Optional[str] = None
    location: Optional[str] = None

    class Config:
        """ForeignIpsByOrg schema config class."""

        orm_mode = True


# --- query_roots(), Issue 622 ---
# Get root domains for specified org
class RootDomainsByOrg(BaseModel):
    """RootDomainsByOrg schema class."""

    root_domain_uid: Optional[str] = None
    root_domain: Optional[str] = None

    class Config:
        """RootDomainsByOrg schema config class."""

        orm_mode = True


# --- query_creds_view(), Issue 623 ---
# Uses VwBreachcomp schema


# --- query_credsbyday_view(), Issue 624 ---
class CredsbydateByOrg(BaseModel):
    """CredsbydateByOrg schema class."""

    mod_date: Optional[str] = None
    no_password: Optional[int] = None
    password_included: Optional[int] = None

    class Config:
        """CredsbydateByOrg schema config class."""

        orm_mode = True


# --- query_breachdetails_view(), Issue 625 ---
class BreachdetailsByOrg(BaseModel):
    """BreachdetailsByOrg schema class."""

    breach_name: Optional[str] = None
    mod_date: Optional[str] = None
    breach_date: Optional[str] = None
    password_included: Optional[int] = None
    number_of_creds: Optional[int] = None

    class Config:
        """BreachdetailsByOrg schema config class."""

        orm_mode = True


# --- query_shodan(), Issue 628 ---
class VwShodanvulnsSuspectedSchema(BaseModel):
    """VwShodanvulnsSuspectedSchema schema class."""

    organizations_uid: Optional[str]
    organization: Optional[str]
    ip: Optional[str]
    port: Optional[str]
    protocol: Optional[str]
    type: Optional[str]
    name: Optional[str]
    # potential_vulns: List[Optional[str]]
    potential_vulns: Optional[List[str]]
    mitigation: Optional[str]
    timestamp: Optional[str]
    product: Optional[str]
    server: Optional[str]
    # tags: List[Optional[str]]
    # domains: List[Optional[str]]
    # hostnames: List[Optional[str]]
    tags: Optional[List[str]]
    domains: Optional[List[str]]
    hostnames: Optional[List[str]]
    isn: Optional[str]
    asn: Optional[int]
    data_source: Optional[str]

    class Config:
        """VwShodanvulnsSuspectedSchema schema config class."""

        orm_mode = True


# --- query_shodan(), Issue 628 ---
class VwShodanvulnsVerifiedSchema(BaseModel):
    """VwShodanvulnsVerifiedSchema schema class."""

    organizations_uid: Optional[str]
    organization: Optional[str]
    ip: Optional[str]
    port: Optional[str]
    protocol: Optional[str]
    timestamp: Optional[str]
    cve: Optional[str]
    severity: Optional[str]
    cvss: Optional[Decimal]
    summary: Optional[str]
    product: Optional[str]
    attack_vector: Optional[str]
    av_description: Optional[str]
    attack_complexity: Optional[str]
    ac_description: Optional[str]
    confidentiality_impact: Optional[str]
    ci_description: Optional[str]
    integrity_impact: Optional[str]
    ii_description: Optional[str]
    availability_impact: Optional[str]
    ai_description: Optional[str]
    # tags: List[Optional[str]]
    # domains: List[Optional[str]]
    # hostnames: List[Optional[str]]
    tags: Optional[List[str]]
    domains: Optional[List[str]]
    hostnames: Optional[List[str]]
    isn: Optional[str]
    asn: Optional[int]
    data_source: Optional[str]

    class Config:
        """VwShodanvulnsVerifiedSchema schema config class."""

        orm_mode = True


# --- query_shodan(), Issue 628 ---
class ShodanAssetsSchema(BaseModel):
    """ShodanAssetsSchema schema class."""

    shodan_asset_uid: Optional[str]
    organizations_uid_id: Optional[str]
    organization: Optional[str]
    ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    timestamp: Optional[str]
    product: Optional[str]
    server: Optional[str]
    # tags: List[Optional[str]]
    # domains: List[Optional[str]]
    # hostnames: List[Optional[str]]
    tags: Optional[List[str]]
    domains: Optional[List[str]]
    hostnames: Optional[List[str]]
    isn: Optional[str]
    asn: Optional[int]
    data_source_uid_id: Optional[str]

    class Config:
        """ShodanAssetsSchema schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class DarkWebDataInput(BaseModel):
    """DarkWebDataInput schema class."""

    org_uid: str
    start_date: str
    end_date: str
    table: str

    class Config:
        """DarkWebDataInput schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class MentionsTable(BaseModel):
    """MentionsTable schema class."""

    mentions_uid: Optional[str] = None
    category: Optional[str] = None
    collection_date: Optional[str] = None
    content: Optional[str] = None
    creator: Optional[str] = None
    date: Optional[str] = None
    sixgill_mention_id: Optional[str] = None
    post_id: Optional[str] = None
    lang: Optional[str] = None
    rep_grade: Optional[str] = None
    site: Optional[str] = None
    site_grade: Optional[str] = None
    title: Optional[str] = None
    type: Optional[str] = None
    url: Optional[str] = None
    comments_count: Optional[str] = None
    sub_category: Optional[str] = None
    tags: Optional[str] = None
    organizations_uid: Optional[str] = None
    data_source_uid: Optional[str] = None
    title_translated: Optional[str] = None
    content_translated: Optional[str] = None
    detected_lang: Optional[str] = None

    class Config:
        """MentionsTable schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class AlertsTable(BaseModel):
    """AlertsTable schema class."""

    alerts_uid: Optional[str] = None
    alert_name: Optional[str] = None
    content: Optional[str] = None
    date: Optional[str] = None
    sixgill_id: Optional[str] = None
    read: Optional[str] = None
    severity: Optional[str] = None
    site: Optional[str] = None
    threat_level: Optional[str] = None
    threats: Optional[str] = None
    title: Optional[str] = None
    user_id: Optional[str] = None
    category: Optional[str] = None
    lang: Optional[str] = None
    organizations_uid_id: Optional[str] = None
    data_source_uid_id: Optional[str] = None
    content_snip: Optional[str] = None
    asset_mentioned: Optional[str] = None
    asset_type: Optional[str] = None

    class Config:
        """AlertsTable schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class VwDarkwebMentionsbydate(BaseModel):
    """VwDarkwebMentionsbydate schema class."""

    organizations_uid: Optional[str] = None
    date: Optional[str] = None
    count: Optional[int] = None

    class Config:
        """VwDarkwebMentionsbydate schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class VwDarkwebInviteonlymarkets(BaseModel):
    """VwDarkwebInviteonlymarkets schema class."""

    organizations_uid: Optional[str] = None
    date: Optional[str] = None
    Site: Optional[str] = None

    class Config:
        """VwDarkwebInviteonlymarkets schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class VwDarkwebSocmediaMostactposts(BaseModel):
    """VwDarkwebSocmediaMostactposts schema class."""

    organizations_uid: Optional[str] = None
    date: Optional[str] = None
    Title: Optional[str] = None
    comments_count: Optional[int] = None

    class Config:
        """VwDarkwebSocmediaMostactposts schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class VwDarkwebMostactposts(BaseModel):
    """VwDarkwebMostactposts schema class."""

    organizations_uid: Optional[str] = None
    date: Optional[str] = None
    Title: Optional[str] = None
    comments_count: Optional[int] = None

    class Config:
        """VwDarkwebMostactposts schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class VwDarkwebExecalerts(BaseModel):
    """VwDarkwebExecalerts schema class."""

    organizations_uid: Optional[str] = None
    date: Optional[str] = None
    Site: Optional[str] = None
    Title: Optional[str] = None
    Events: Optional[int] = None

    class Config:
        """VwDarkwebExecalerts schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class VwDarkwebAssetalerts(BaseModel):
    """VwDarkwebAssetalerts schema class."""

    organizations_uid: Optional[str] = None
    date: Optional[str] = None
    Site: Optional[str] = None
    Title: Optional[str] = None
    Events: Optional[int] = None

    class Config:
        """VwDarkwebAssetalerts schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class VwDarkwebThreatactors(BaseModel):
    """VwDarkwebThreatactors schema class."""

    organizations_uid: Optional[str] = None
    date: Optional[str] = None
    Creator: Optional[str] = None
    Grade: Optional[float] = None

    class Config:
        """VwDarkwebThreatactors schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class VwDarkwebPotentialthreats(BaseModel):
    """VwDarkwebPotentialthreats schema class."""

    organizations_uid: Optional[str] = None
    date: Optional[str] = None
    Site: Optional[str] = None
    Threats: Optional[str] = None

    class Config:
        """VwDarkwebPotentialthreats schema config class."""

        orm_mode = True


# --- query_darkweb(), Issue 629 ---
class VwDarkwebSites(BaseModel):
    """VwDarkwebSites schema class."""

    organizations_uid: Optional[str] = None
    date: Optional[str] = None
    Site: Optional[str] = None

    class Config:
        """VwDarkwebSites schema config class."""

        orm_mode = True


# --- query_darkweb_cves(), Issue 630 ---
class TopCvesTable(BaseModel):
    """TopCvesRecord schema class."""

    top_cves_uid: str
    cve_id: str
    dynamic_rating: str
    nvd_base_score: str
    date: str
    summary: str
    data_source_uid_id: str

    class Config:
        """TopCvesRecord schema config class."""

        orm_mode = True


# --- query_darkweb_cves(), Issue 630 ---
class DarkWebCvesTaskResp(BaseModel):
    """DarkWebCvesTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[TopCvesTable]] = None
    error: Optional[str] = None


# --- execute_scorecard(), Issue 632 ---
# Insert record into report_summary_stats, input
class RSSInsertInput(BaseModel):
    """RSSInsertInput schema class."""

    organizations_uid: str
    start_date: str
    end_date: str
    ip_count: int
    root_count: int
    sub_count: int
    num_ports: int  # ports_count: int
    creds_count: int
    breach_count: int
    cred_password_count: int
    domain_alert_count: int
    suspected_domain_count: int
    insecure_port_count: int
    verified_vuln_count: int
    suspected_vuln_count: int
    suspected_vuln_addrs_count: int
    threat_actor_count: int
    dark_web_alerts_count: int
    dark_web_mentions_count: int
    dark_web_executive_alerts_count: int
    dark_web_asset_alerts_count: int
    pe_number_score: str  # may be "NA"
    pe_letter_grade: str  # may be "NA"
    cidr_count: int
    port_protocol_count: int
    software_count: int
    foreign_ips_count: int

    class Config:
        """RSSInsertInput schema config class."""

        orm_mode = True


# --- query_previous_period(), Issue 634 ---
# Get prev. report period data from report_summary_stats
class RSSPrevPeriod(BaseModel):
    """RSSPrevPeriod schema class."""

    ip_count: Optional[int] = None
    root_count: Optional[int] = None
    sub_count: Optional[int] = None
    cred_password_count: Optional[int] = None
    suspected_vuln_addrs_count: Optional[int] = None
    suspected_vuln_count: Optional[int] = None
    insecure_port_count: Optional[int] = None
    threat_actor_count: Optional[int] = None

    class Config:
        """RSSPrevPeriod schema config class."""

        orm_mode = True


# --- query_previous_period(), Issue 634 ---
# Get prev. report period data from report_summary_stats, input
class RSSPrevPeriodInput(BaseModel):
    """RSSPrevPeriodInput schema class."""

    org_uid: str
    prev_end_date: str

    class Config:
        """RSSPrevPeriodInput schema config class."""

        orm_mode = True


# ---------- General PE Score Schemas, 635 ----------
# --- reported orgs schema, Issue 635 ---
# List of reported organizations schema
class ReportedOrgs(BaseModel):
    """ReportedOrgs schema class."""

    organizations_uid: str

    class Config:
        """ReportedOrgs schema config class."""

        orm_mode = True


# --- reported orgs schema, Issue 635 ---
# List of reported organizations w/ cyhy db name schema
class ReportedOrgsCyhy(BaseModel):
    """ReportedOrgsCyhy schema class."""

    organizations_uid: str
    cyhy_db_name: str

    class Config:
        """ReportedOrgsCyhy schema config class."""

        orm_mode = True


# ---------- PE Score Historical Data, 635 ----------
# --- pescore_hist_domain_alert(), Issue 635 ---
# Get pescore_hist_domain_alert data for the specified period
class PEScoreHistDomainAlert(BaseModel):
    """PEScoreHistDomainAlert schema class."""

    organizations_uid: str
    date: str

    class Config:
        """PEScoreHistDomainAlert schema config class."""

        orm_mode = True


# --- pescore_hist_domain_alert(), Issue 635 ---
# Get pescore_hist_domain_alert data for the specified period, consolidated resp
class PEScoreHistDomainAlertResp(BaseModel):
    """PEScoreHistDomainAlertResp schema class."""

    reported_orgs: List[ReportedOrgsCyhy]
    hist_domain_alert_data: List[PEScoreHistDomainAlert]

    class Config:
        """PEScoreHistDomainAlertResp schema config class."""

        orm_mode = True


# --- pescore_hist_domain_alert(), Issue 635 ---
# Get pescore_hist_domain_alert data for the specified period, task resp
class PEScoreHistDomainAlertTaskResp(BaseModel):
    """PEScoreHistDomainAlertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[PEScoreHistDomainAlertResp] = None
    error: Optional[str] = None


# --- pescore_hist_darkweb_alert(), Issue 635 ---
# Get pescore_hist_darkweb_alert data for the specified period
class PEScoreHistDarkwebAlert(BaseModel):
    """PEScoreHistDarkwebAlert schema class."""

    organizations_uid: str
    date: str

    class Config:
        """PEScoreHistDarkwebALert schema config class."""

        orm_mode = True


# --- pescore_hist_darkweb_alert(), Issue 635 ---
# Get pescore_hist_darkweb_alert data for the specified period, consolidated resp
class PEScoreHistDarkwebAlertResp(BaseModel):
    """PEScoreHistDarkwebAlertResp schema class."""

    reported_orgs: List[ReportedOrgsCyhy]
    hist_darkweb_alert_data: List[PEScoreHistDarkwebAlert]

    class Config:
        """PEScoreHistDarkwebAlertResp schema config class."""

        orm_mode = True


# --- pescore_hist_darkweb_alert(), Issue 635 ---
# Get pescore_hist_darkweb_alert data for the specified period, task resp
class PEScoreHistDarkwebAlertTaskResp(BaseModel):
    """PEScoreHistDarkwebAlertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[PEScoreHistDarkwebAlertResp] = None
    error: Optional[str] = None


# --- pescore_hist_darkweb_ment(), Issue 635 ---
# Get pescore_hist_darkweb_ment data for the specified period
class PEScoreHistDarkwebMent(BaseModel):
    """PEScoreHistDarkwebMent schema class."""

    organizations_uid: str
    date: str
    count: int

    class Config:
        """PEScoreHistDarkwebMent schema config class."""

        orm_mode = True


# --- pescore_hist_darkweb_ment(), Issue 635 ---
# Get pescore_hist_darkweb_ment data for the specified period, consolidated resp
class PEScoreHistDarkwebMentResp(BaseModel):
    """PEScoreHistDarkwebMentResp schema class."""

    reported_orgs: List[ReportedOrgsCyhy]
    hist_darkweb_ment_data: List[PEScoreHistDarkwebMent]

    class Config:
        """PEScoreHistDarkwebMentResp schema config class."""

        orm_mode = True


# --- pescore_hist_darkweb_ment(), Issue 635 ---
# Get pescore_hist_darkweb_ment data for the specified period, task resp
class PEScoreHistDarkwebMentTaskResp(BaseModel):
    """PEScoreHistDarkwebMentTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[PEScoreHistDarkwebMentResp] = None
    error: Optional[str] = None


# --- pescore_hist_cred(), Issue 635 ---
# Get pescore_hist_cred data for the specified period
class PEScoreHistCred(BaseModel):
    """PEScoreHistCred schema class."""

    organizations_uid: str
    mod_date: str
    no_password: int
    password_included: int

    class Config:
        """PEScoreHistCred schema config class."""

        orm_mode = True


# --- pescore_hist_cred(), Issue 635 ---
# Get pescore_hist_cred data for the specified period, consolidated resp
class PEScoreHistCredResp(BaseModel):
    """PEScoreHistCredResp schema class."""

    reported_orgs: List[ReportedOrgsCyhy]
    hist_cred_data: List[PEScoreHistCred]

    class Config:
        """PEScoreHistCredResp schema config class."""

        orm_mode = True


# --- pescore_hist_cred(), Issue 635 ---
# Get pescore_hist_cred data for the specified period, task resp
class PEScoreHistCredTaskResp(BaseModel):
    """PEScoreHistCredTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[PEScoreHistCredResp] = None
    error: Optional[str] = None


# ---------- PE Score Base Metrics Data, 635 ----------
# --- pescore_base_metrics(), Issue 635 ---
# Get data for CRED component of pescore_base_metrics
class PEScoreCred(BaseModel):
    """PEScoreCred schema class."""

    organizations_uid: str
    password_included: int
    no_password: int

    class Config:
        """PEScoreCred schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for BREACH component of pescore_base_metrics
class PEScoreBreach(BaseModel):
    """PEScoreBreach schema class."""

    organizations_uid: str
    num_breaches: int

    class Config:
        """PEScoreBreach schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DOMAIN SUSPECTED component of pescore_base_metrics
class PEScoreDomainSus(BaseModel):
    """PEScoreDomainSus schema class."""

    organizations_uid: str
    num_sus_domain: int

    class Config:
        """PEScoreDomainSus schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DOMAIN ALERT component of pescore_base_metrics
class PEScoreDomainAlert(BaseModel):
    """PEScoreDomainAlert schema class."""

    organizations_uid: str
    num_alert_domain: int

    class Config:
        """PEscoreDomainAlert schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for VERIF VULN component of pescore_base_metrics
class PEScoreVulnVerif(BaseModel):
    """PEScoreVulnVerif schema class."""

    organizations_uid: str
    num_verif_vulns: int

    class Config:
        """PESCoreVulnVerif schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for UNVERIF VULN component of pescore_base_metrics
class PEScoreVulnUnverif(BaseModel):
    """PEScoreVulnUnverif schema class."""

    organizations_uid: str
    num_assets_unverif_vulns: int

    class Config:
        """PEScoreVulnUnverif schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for PORT component of pescore_base_metrics
class PEScoreVulnPort(BaseModel):
    """PEScoreVulnPort schema class."""

    organizations_uid: str
    num_risky_ports: int

    class Config:
        """PEscoreVulnPort schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DARKWEB ALERT component of pescore_base_metrics
class PEScoreDarkwebAlert(BaseModel):
    """PEScoreDarkwebAlert schema class."""

    organizations_uid: str
    num_dw_alerts: int

    class Config:
        """PEScoreDarkwebAlert schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DARKWEB MENTION component of pescore_base_metrics
class PEScoreDarkwebMent(BaseModel):
    """PEScoreDarkwebMent schema class."""

    organizations_uid: str
    num_dw_mentions: int

    class Config:
        """PEScoreDarkwebMent schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DARKWEB THREAT component of pescore_base_metrics
class PEScoreDarkwebThreat(BaseModel):
    """PEScoreDarkwebThreat schema class."""

    organizations_uid: str
    num_dw_threats: int

    class Config:
        """PEScoreDarkwebThreat schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for DARKWEB INVITE component of pescore_base_metrics
class PEScoreDarkwebInv(BaseModel):
    """PEScoreDarkwebInv schema class."""

    organizations_uid: str
    num_dw_invites: int

    class Config:
        """PEScoreDarwkebInv schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get data for ATTACKSURFACE component of pescore_base_metrics
class PEScoreAttackSurface(BaseModel):
    """PEScoreAttackSurface schema class."""

    organizations_uid: str
    cyhy_db_name: Optional[str] = None
    num_ports: Optional[int] = None
    num_root_domain: Optional[int] = None
    num_sub_domain: Optional[int] = None
    num_ips: Optional[int] = None
    num_cidrs: Optional[int] = None
    num_ports_protocols: Optional[int] = None
    num_software: Optional[int] = None
    num_foreign_ips: Optional[int] = None

    class Config:
        """PEScoreAttackSurface schema config class."""

        orm_mode = True


# --- pescore_base_metrics(), Issue 635 ---
# Get all base metric data for PE score
class PEScoreBaseMetrics(BaseModel):
    """PEScoreBaseMetrics schema class."""

    reported_orgs: List[ReportedOrgs]
    cred_data: List[PEScoreCred]
    breach_data: List[PEScoreBreach]
    domain_sus_data: List[PEScoreDomainSus]
    domain_alert_data: List[PEScoreDomainAlert]
    vuln_verif_data: List[PEScoreVulnVerif]
    vuln_unverif_data: List[PEScoreVulnUnverif]
    vuln_port_data: List[PEScoreVulnPort]
    darkweb_alert_data: List[PEScoreDarkwebAlert]
    darkweb_ment_data: List[PEScoreDarkwebMent]
    darkweb_threat_data: List[PEScoreDarkwebThreat]
    darkweb_inv_data: List[PEScoreDarkwebInv]
    attacksurface_data: List[PEScoreAttackSurface]


# --- pescore_base_metrics(), Issue 635 ---
# Get all base metric data for PE score, task resp
class PEScoreBaseMetricsTaskResp(BaseModel):
    """PEScoreBaseMetricsTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[PEScoreBaseMetrics] = None
    error: Optional[str] = None


# --- get_new_cves_list(), Issue 636 ---
# Get any detected CVEs that aren't in the cve_info table yet
class VwPEScoreCheckNewCVE(BaseModel):
    """VwPEScoreCheckNewCVE schema class."""

    cve_name: str

    class Config:
        """VwPEScoreCheckNewCVE schema config class."""

        orm_mode = True


# --- upsert_new_cves(), Issue 637 ---
# Upsert new CVEs into cve_info
class CVEInfoInsert(BaseModel):
    """CVEInfoInsert schema class."""

    cve_name: str
    cvss_2_0: float
    cvss_2_0_severity: str
    cvss_2_0_vector: str
    cvss_3_0: float
    cvss_3_0_severity: str
    cvss_3_0_vector: str
    dve_score: float

    class Config:
        """CVEInfoInsert schema config class."""

        orm_mode = True


# --- upsert_new_cves(), Issue 637 ---
# Upsert new CVEs into cve_info, input
class CVEInfoInsertInput(BaseModel):
    """CVEInfoInsertInput schema class."""

    new_cves: List[CVEInfoInsert]

    class Config:
        """CVEInfoInsertInput schema config class."""

        orm_mode = True


# --- upsert_new_cves(), Issue 637 ---
# Upsert new CVEs into cve_info, task resp
class CVEInfoInsertTaskResp(BaseModel):
    """CVEInfoInsertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[str] = None
    error: Optional[str] = None


# --- get_intelx_breaches(), Issue 641 ---
# Get IntelX breaches
class CredBreachIntelX(BaseModel):
    """CredBreachIntelX schema class."""

    breach_name: str
    credential_breaches_uid: str

    class Config:
        """CredBreachIntelX schema config class."""

        orm_mode = True


# --- get_intelx_breaches(), Issue 641 ---
# Get IntelX breaches, input
class CredBreachIntelXInput(BaseModel):
    """CredBreachIntelXInput schema class."""

    source_uid: str

    class Config:
        """CredBreachIntelXInput schema config class."""

        orm_mode = True


# --- get_intelx_breaches(), Issue 641 ---
# Get IntelX breaches, task resp
class CredBreachIntelXTaskResp(BaseModel):
    """CredBreachIntelXTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[CredBreachIntelX]] = None
    error: Optional[str] = None


# --- insert_sixgill_alerts(), Issue 653 ---
class AlertsInsert(BaseModel):
    """AlertsInsert schema class."""

    alert_name: Optional[str] = None
    content: Optional[str] = None  # PROBLEM
    date: Optional[str] = None
    sixgill_id: Optional[str] = None
    read: Optional[str] = None
    severity: Optional[str] = None
    site: Optional[str] = None
    threat_level: Optional[str] = None
    threats: Optional[str] = None  # PROBLEM
    title: Optional[str] = None
    user_id: Optional[str] = None
    category: Optional[str] = None
    lang: Optional[str] = None  # PROBLEM
    organizations_uid: Optional[str] = None  # PROBLEM
    data_source_uid: Optional[str] = None  # PROBLEM
    content_snip: Optional[str] = None  # PROBLEM
    asset_mentioned: Optional[str] = None  # PROBLEM
    asset_type: Optional[str] = None  # PROBLEM

    class Config:
        """AlertsInsert schema config class."""

        orm_mode = True


# --- insert_sixgill_alerts(), Issue 653 ---
class AlertsInsertInput(BaseModel):
    """AlertsInsertInput schema class."""

    new_alerts: List[AlertsInsert]

    class Config:
        """AlertsInsertInput schema config class."""

        orm_mode = True


# --- insert_sixgill_alerts(), Issue 653 ---
class AlertsInsertTaskResp(BaseModel):
    """AlertsInsertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[str] = None
    error: Optional[str] = None


# --- insert_sixgill_mentions(), Issue 654 ---
class MentionsInsert(BaseModel):
    """MentionsInsert schema class."""

    organizations_uid: Optional[str] = None
    data_source_uid: Optional[str] = None
    category: Optional[str] = None
    collection_date: Optional[str] = None
    content: Optional[str] = None
    creator: Optional[str] = None
    date: Optional[str] = None
    sixgill_mention_id: Optional[str] = None
    lang: Optional[str] = None
    post_id: Optional[str] = None
    rep_grade: Optional[str] = None
    site: Optional[str] = None
    site_grade: Optional[str] = None
    sub_category: Optional[str] = None
    title: Optional[str] = None
    type: Optional[str] = None
    url: Optional[str] = None
    comments_count: Optional[str] = None
    tags: Optional[str] = None

    class Config:
        """MentionsInsert schema config class."""

        orm_mode = True


# --- insert_sixgill_mentions(), Issue 654 ---
class MentionsInsertInput(BaseModel):
    """MentionsInsertInput schema class."""

    new_mentions: List[MentionsInsert]

    class Config:
        """MentionsInsertInput schema config class."""

        orm_mode = True


# --- insert_sixgill_mentions(), Issue 654 ---
class MentionsInsertTaskResp(BaseModel):
    """MentionsInsertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[str] = None
    error: Optional[str] = None


# --- insert_sixgill_breaches(), Issue 655 ---
class CredBreachesSixgillInsert(BaseModel):
    """CredBreachesSixgillInsert schema class."""

    breach_name: str
    description: str
    breach_date: str
    password_included: bool
    data_source_uid: str
    modified_date: str

    class Config:
        """CredBreachesSixgillInsert schema config class."""

        orm_mode = True


# --- insert_sixgill_breaches(), Issue 655 ---
class CredBreachesSixgillInsertInput(BaseModel):
    """CredBreachesSixgillInsertInput schema class."""

    new_breaches: List[CredBreachesSixgillInsert]

    class Config:
        """CredBreachesSixgillInsertInput schema config class."""

        orm_mode = True


# --- insert_sixgill_breaches(), Issue 655 ---
class CredBreachesSixgillInsertTaskResp(BaseModel):
    """CredBreachesSixgillInsertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[str] = None
    error: Optional[str] = None


# --- insert_sixgill_credentials(), Issue 656 ---
class CredExpSixgillInsert(BaseModel):
    """CredExpSixgillInsert schema class."""

    modified_date: str
    sub_domain: str
    email: str
    hash_type: str
    name: str
    login_id: str
    password: str
    phone: str
    breach_name: str
    organizations_uid: str
    data_source_uid: str
    credential_breaches_uid: str

    class Config:
        """CredExpSixgillInsert schema config class."""

        orm_mode = True


# --- insert_sixgill_credentials(), Issue 656 ---
class CredExpSixgillInsertInput(BaseModel):
    """CredExpSixgillInsertInput schema class."""

    new_exposures: List[CredExpSixgillInsert]

    class Config:
        """CredExpSixgillInsertInput schema config class."""

        orm_mode = True


# --- insert_sixgill_credentials(), Issue 656 ---
class CredExpSixgillInsertTaskResp(BaseModel):
    """CredExpSixgillInsertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[str] = None
    error: Optional[str] = None


# --- insert_sixgill_topCVEs(), Issue 657 ---
# Insert multiple records into the top_cves table
class TopCVEsInsert(BaseModel):
    """TopCVEsInsert schema class."""

    cve_id: str
    dynamic_rating: Optional[str] = None
    nvd_base_score: Optional[str] = None
    date: str
    summary: Optional[str] = None
    data_source_uid: Optional[str] = None

    class Config:
        """TopCVEsInsert schema config class."""

        orm_mode = True


# --- insert_sixgill_topCVEs(), Issue 657 ---
# Insert multiple records into the top_cves table, input
class TopCVEsInsertInput(BaseModel):
    """TopCVEsInsertInput schema class."""

    new_topcves: List[TopCVEsInsert]

    class Config:
        """TopCVEsInsertInput schema config class."""

        orm_mode = True


# --- insert_sixgill_topCVEs(), Issue 657 ---
class TopCVEsInsertTaskResp(BaseModel):
    """TopCVEsInsertTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[str] = None
    error: Optional[str] = None


# --- execute_dnsmonitor_data(), Issue 659 ---
# Insert multiple records into the domain_permutations table
class DomainPermuInsert(BaseModel):
    """DomainPermuInsert schema class."""

    organizations_uid: str
    sub_domain_uid: Optional[str] = None
    data_source_uid: Optional[str] = None
    domain_permutation: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    mail_server: Optional[str] = None
    name_server: Optional[str] = None
    date_observed: Optional[str] = None

    class Config:
        """DomainPermuInsert schema config class."""

        orm_mode = True


# --- execute_dnsmonitor_data(), Issue 659 ---
# Insert multiple records into the domain_permutations table, input
class DomainPermuInsertInput(BaseModel):
    """DomainPermuInsertInput schema class."""

    insert_data: List[DomainPermuInsert]

    class Config:
        """DomainPermuInsertInput schema config class."""

        orm_mode = True


# --- execute_dnsmonitor_alert_data(), Issue 660 ---
# Insert multiple records into the domain_alerts table
class DomainAlertsInsert(BaseModel):
    """DomainAlertsInsert schema class."""

    organizations_uid: str
    sub_domain_uid: Optional[str] = None
    data_source_uid: Optional[str] = None
    alert_type: Optional[str] = None
    message: Optional[str] = None
    previous_value: Optional[str] = None
    new_value: Optional[str] = None
    date: Optional[str] = None

    class Config:
        """DomainAlertsInsert schema config class."""

        orm_mode = True


# --- execute_dnsmonitor_alert_data(), Issue 660 ---
# Insert multiple records into the domain_alerts table, input
class DomainAlertsInsertInput(BaseModel):
    """DomainAlertsInsertInput schema class."""

    insert_data: List[DomainAlertsInsert]

    class Config:
        """DomainAlertsInsertInput schema config class."""

        orm_mode = True


# --- addRootdomain(), Issue 661 ---
# Insert single root domain into root_domains table, input
class RootDomainsSingleInsertInput(BaseModel):
    """RootDomainsSingleInsertInput schema class."""

    root_domain: str
    pe_org_uid: str
    source_uid: str
    org_name: str

    class Config:
        """RootDomainsSingleInsertInput schema config class."""

        orm_mode = True


# --- addSubdomain(), Issue 662 ---
# Insert single sub domain into sub_domains table, input
class SubDomainsSingleInsertInput(BaseModel):
    """SubDomainsSingleInsertInput schema class."""

    domain: str
    pe_org_uid: str
    root: Optional[bool] = None

    class Config:
        """SubDomainsSingleInsertInput schema config class."""

        orm_mode = True


# --- insert_intelx_breaches(), Issue 663 ---
# Insert bulk IntelX breach data into credential_breaches table
class CredBreachesIntelxInsert(BaseModel):
    """CredBreachesIntelxInsert schema class."""

    breach_name: str
    description: str
    breach_date: str
    added_date: str
    modified_date: str
    password_included: bool
    data_source_uid: str

    class Config:
        """CredBreachesIntelxInsert schema config class."""

        orm_mode = True


# --- insert_intelx_breaches(), Issue 663 ---
# Insert bulk IntelX breach data into credential_breaches table, input
class CredBreachesIntelxInsertInput(BaseModel):
    """CredBreachesIntelxInsertInput schema class."""

    breach_data: List[CredBreachesIntelxInsert]

    class Config:
        """CredBreachesIntelxInsertInput schema config class."""

        orm_mode = True


# --- insert_intelx_credentials(), Issue 664 ---
# Insert bulk IntelX credential data into credential_exposures table
class CredExpIntelxInsert(BaseModel):
    """CredExpIntelxInsert schema class."""

    email: str
    organizations_uid: str
    root_domain: str
    sub_domain: str
    breach_name: str
    modified_date: str
    data_source_uid: str
    password: str
    hash_type: str
    intelx_system_id: str

    class Config:
        """CredExpIntelxInsert schema config class."""

        orm_mode = True


# --- insert_intelx_credentials(), Issue 664 ---
# Insert bulk IntelX credential data into credential_exposures table, input
class CredExpIntelxInsertInput(BaseModel):
    """CredExpIntelxInsertInput schema class."""

    exp_data: List[CredExpIntelxInsert]

    class Config:
        """CredExpIntelxInsertInput schema config class."""

        orm_mode = True


# --- xpanse endpoint, Issue 682 ---
class XpanseBusinessUnitsInsert(BaseModel):
    """XpanseBusinessUnitsInsert schema class."""

    # xpanse_business_unit_uid: Optional[Any]
    entity_name: str
    state: Optional[str] = None
    county: Optional[str] = None
    city: Optional[str] = None
    sector: Optional[str] = None
    entity_type: Optional[str] = None
    region: Optional[str] = None
    rating: Optional[int] = None


# --- xpanse endpoint, Issue 682 ---
class XpanseAsset(BaseModel):
    """XpanseAsset schema class."""

    # xpanse_asset_uid = models.UUIDField(primary_key=True, default=uuid.uuid1)
    asm_id: Optional[str] = None
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
    last_observed: Optional[datetime] = None
    first_observed: Optional[datetime] = None
    externally_detected_providers: Optional[List[str]] = None
    created: Optional[datetime] = None
    ips: Optional[List[str]] = None
    active_external_services_types: Optional[List[str]] = None
    domain: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_algorithm: Optional[str] = None
    certificate_classifications: Optional[List[str]] = None
    resolves: Optional[bool] = None
    # details
    top_level_asset_mapper_domain: Optional[str] = None
    domain_asset_type: Optional[Dict] = None  # This was JSON
    is_paid_level_domain: Optional[bool] = None
    domain_details: Optional[Dict] = None  # This was JSON
    dns_zone: Optional[str] = None
    latest_sampled_ip: Optional[int] = None

    recent_ips: Optional[List[Dict]] = None  # This was JSON
    external_services: Optional[List[Dict]] = None  # This was JSON
    externally_inferred_vulnerability_score: Optional[float] = None
    externally_inferred_cves: Optional[List[str]] = None
    explainers: Optional[List[str]] = None
    tags: Optional[List[str]] = None


# --- xpanse endpoint, Issue 682 ---
class XpanseCve(BaseModel):
    """XpanseCVE schema class."""

    cve_id: Optional[str] = None
    cvss_score_v2: Optional[float] = None
    cve_severity_v2: Optional[str] = None
    cvss_score_v3: Optional[float] = None
    cve_severity_v3: Optional[str] = None


# --- xpanse endpoint, Issue 682 ---
class XpanseCveMatch(BaseModel):
    """XpanseCveMatch schema class."""

    inferred_cve_match_type: Optional[str] = None
    product: Optional[str] = None
    confidence: Optional[str] = None
    vendor: Optional[str] = None
    version_number: Optional[str] = None
    activity_status: Optional[str] = None
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None


# --- xpanse endpoint, Issue 682 ---
class XpanseService(BaseModel):
    """XpanseService schema class."""

    # xpanse_service_uid = models.UUIDField(primary_key=True, default=uuid.uuid1)
    service_id: Optional[str] = None
    service_name: Optional[str] = None
    service_type: Optional[str] = None
    ip_address: Optional[List[str]] = None
    domain: Optional[List[str]] = None
    externally_detected_providers: Optional[List[str]] = None
    is_active: Optional[str] = None
    first_observed: Optional[datetime] = None
    last_observed: Optional[datetime] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    active_classifications: Optional[List[str]] = None
    inactive_classifications: Optional[List[str]] = None
    discovery_type: Optional[str] = None
    externally_inferred_vulnerability_score: Optional[float] = None
    externally_inferred_cves: Optional[List[str]] = None
    service_key: Optional[str] = None
    service_key_type: Optional[str] = None

    cves: Optional[List[Tuple[XpanseCve, XpanseCveMatch]]] = None


# --- xpanse endpoint, Issue 682 ---
class XpanseAlertInsert(BaseModel):
    """XpanseAlertInsert schema class."""

    # xpanse_alert_uid =  models.UUIDField(primary_key=True, default=uuid.uuid1)
    time_pulled_from_xpanse: Optional[datetime] = None
    alert_id: str
    detection_timestamp: Optional[datetime] = None
    alert_name: Optional[str] = None
    # endpoint_id ???,
    description: Optional[str] = None
    host_name: Optional[str] = None
    alert_action: Optional[str] = None
    # user_name ??? null,
    # mac_addresses ??? null,
    # source ??? null,
    action_pretty: Optional[str] = None
    # category ??? null,
    # project ??? null,
    # cloud_provider ??? null,
    # resource_sub_type ??? null,
    # resource_type ??? null,
    action_country: Optional[List[str]] = None
    # event_type ??? null,
    # is_whitelisted ??? null,
    # image_name ??? null,
    # action_local_ip ??? null,
    # action_local_port ??? null,
    # action_external_hostname ??? null,
    # action_remote_ip ??? null,
    action_remote_port: Optional[List[int]] = None
    # "matching_service_rule_id ??? null,
    starred: Optional[bool] = None
    external_id: Optional[str] = None
    related_external_id: Optional[str] = None
    alert_occurrence: Optional[int] = None
    severity: Optional[str] = None
    matching_status: Optional[str] = None
    # end_match_attempt_ts ??? null,
    local_insert_ts: Optional[datetime] = None
    last_modified_ts: Optional[datetime] = None
    case_id: Optional[int] = None
    # deduplicate_tokens ??? null,
    # filter_rule_id ??? null,
    # event_id ??? null,
    event_timestamp: Optional[List[datetime]] = None
    # action_local_ip_v6 ??? null,
    # action_remote_ip_v6 ??? null,
    alert_type: Optional[str] = None
    resolution_status: Optional[str] = None
    resolution_comment: Optional[str] = None
    # dynamic_fields ??? null,
    tags: Optional[List[str]] = None
    # malicious_urls ??? null,
    last_observed: Optional[datetime] = None
    country_codes: Optional[List[str]] = None
    cloud_providers: Optional[List[str]] = None
    ipv4_addresses: Optional[List[str]] = None
    # ipv6_addresses ??? null,
    domain_names: Optional[List[str]] = None
    service_ids: Optional[List[str]] = None
    website_ids: Optional[List[str]] = None
    asset_ids: Optional[List[str]] = None
    certificate: Optional[Dict] = None  # This was JSON
    # {
    #            issuerName": "IOS-Self-Signed-Certificate-782645061",
    #            subjectName": "IOS-Self-Signed-Certificate-782645061",
    #            validNotBefore": 1398850008000,
    #            validNotAfter": 1577836800000,
    #            serialNumber": "1"
    # },
    port_protocol: Optional[str] = None
    # business_unit_hierarchies
    attack_surface_rule_name: Optional[str] = None
    remediation_guidance: Optional[str] = None
    asset_identifiers: Optional[List[Dict]] = None  # This was JSON

    business_units: List[str] = []
    services: List[XpanseService] = []
    assets: List[XpanseAsset] = []


# --- xpanse endpoint, Issue 682 ---
class XpanseCveOutput(BaseModel):
    """XpanseCveOutput schema class."""

    cve_id: Optional[str] = None
    cvss_score_v2: Optional[str] = None
    cve_severity_v2: Optional[str] = None
    cvss_score_v3: Optional[str] = None
    cve_severity_v3: Optional[str] = None
    inferred_cve_match_type: Optional[str] = None
    product: Optional[str] = None
    confidence: Optional[str] = None
    vendor: Optional[str] = None
    version_number: Optional[str] = None
    activity_status: Optional[str] = None
    first_observed: Optional[str] = None
    last_observed: Optional[str] = None


# --- xpanse endpoint, Issue 682 ---
class XpanseServiceOutput(BaseModel):
    """XpanseServiceOutput schema class."""

    service_id: Optional[str] = None
    service_name: Optional[str] = None
    service_type: Optional[str] = None
    ip_address: Optional[List[str]] = None
    domain: Optional[List[str]] = None
    externally_detected_providers: Optional[List[str]] = None
    is_active: Optional[str] = None
    first_observed: Optional[str] = None
    last_observed: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    active_classifications: Optional[List[str]] = None
    inactive_classifications: Optional[List[str]] = None
    discovery_type: Optional[str] = None
    externally_inferred_vulnerability_score: Optional[str] = None
    externally_inferred_cves: Optional[List[str]] = None
    service_key: Optional[str] = None
    service_key_type: Optional[str] = None
    cves: Optional[List[XpanseCveOutput]] = None


# --- xpanse endpoint, Issue 682 ---
class XpanseVulnOutput(BaseModel):
    """XpanseVulnOutput schhema class."""

    alert_name: Optional[str] = None
    description: Optional[str] = None
    last_modified_ts: Optional[datetime] = None
    local_insert_ts: Optional[datetime] = None
    event_timestamp: Optional[List[datetime]] = None
    host_name: Optional[str] = None
    alert_action: Optional[str] = None
    action_country: Optional[List[str]] = None
    action_remote_port: Optional[List[int]] = None
    external_id: Optional[str] = None
    related_external_id: Optional[str] = None
    alert_occurrence: Optional[int] = None
    severity: Optional[str] = None
    matching_status: Optional[str] = None
    alert_type: Optional[str] = None
    resolution_status: Optional[str] = None
    resolution_comment: Optional[str] = None
    last_observed: Optional[str] = None
    country_codes: Optional[List[str]] = None
    cloud_providers: Optional[List[str]] = None
    ipv4_addresses: Optional[List[str]] = None
    domain_names: Optional[List[str]] = None
    port_protocol: Optional[str] = None
    time_pulled_from_xpanse: Optional[str] = None
    action_pretty: Optional[str] = None
    attack_surface_rule_name: Optional[str] = None
    certificate: Optional[Dict] = None
    remediation_guidance: Optional[str] = None
    asset_identifiers: Optional[List[Dict]] = None
    services: Optional[List[XpanseServiceOutput]] = None


# --- xpanse endpoint, Issue 682 ---
class XpanseVulnPullInput(BaseModel):
    """XpanseVulnPullInput schema class."""

    business_unit: str
    modified_datetime: Optional[datetime] = None

    class Config:
        """XpanseVulnPullInput schema config class."""

        orm_mode = True


# --- xpanse endpoint, Issue 682 ---
class XpanseVulnPullTaskResp(BaseModel):
    """XpanseVulnPullTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[XpanseVulnOutput]] = None
    error: Optional[str] = None


# --- NIST CVE endpoint, Issue 696 ---
class CpeProduct(BaseModel):
    """CpeProduct schema class."""

    cpe_product_name: str
    version_number: str
    vender: str


# --- NIST CVE endpoint, Issue 696 ---
class CveWithProducts(BaseModel):
    """CveWithProducts schema class."""

    cve_uid: Optional[Any]
    cve_name: Optional[str]
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    vuln_status: Optional[str] = None
    description: Optional[str] = None
    cvss_v2_source: Optional[str] = None
    cvss_v2_type: Optional[str] = None
    cvss_v2_version: Optional[str] = None
    cvss_v2_vector_string: Optional[str] = None
    cvss_v2_base_score: Optional[float] = None
    cvss_v2_base_severity: Optional[str] = None
    cvss_v2_exploitability_score: Optional[float] = None
    cvss_v2_impact_score: Optional[float] = None
    cvss_v3_source: Optional[str] = None
    cvss_v3_type: Optional[str] = None
    cvss_v3_version: Optional[str] = None
    cvss_v3_vector_string: Optional[str] = None
    cvss_v3_base_score: Optional[float] = None
    cvss_v3_base_severity: Optional[str] = None
    cvss_v3_exploitability_score: Optional[float] = None
    cvss_v3_impact_score: Optional[float] = None
    cvss_v4_source: Optional[str] = None
    cvss_v4_type: Optional[str] = None
    cvss_v4_version: Optional[str] = None
    cvss_v4_vector_string: Optional[str] = None
    cvss_v4_base_score: Optional[float] = None
    cvss_v4_base_severity: Optional[str] = None
    cvss_v4_exploitability_score: Optional[float] = None
    cvss_v4_impact_score: Optional[float] = None
    weaknesses: Optional[List[str]] = None
    reference_urls: Optional[List[str]] = None
    cpe_list: Optional[List[str]] = None
    vender_product: Optional[Dict[str, List[CpeProduct]]] = None

    class Config:
        """CveWithProducts schema config class."""

        orm_mode = True
        validate_assignment = True


# --- NIST CVE endpoint, Issue 696 ---
class CvePagedResult(BaseModel):
    """SubDomainPagedResult schema class."""

    total_pages: int
    current_page: int
    data: List[CveWithProducts]


# --- NIST CVE endpoint, Issue 696 ---
class CvePagedInput(BaseModel):
    """CvePagedInput schema class."""

    modified_datetime: Optional[datetime] = None
    page: int
    per_page: int

    class Config:
        """CvePagedInput schema config class."""

        orm_mode = True


# --- NIST CVE endpoint, Issue 696 ---
class CvePagedTaskResp(BaseModel):
    """SubDomainPagedTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[CvePagedResult] = None
    error: Optional[str] = None


# --- NIST CVE endpoint, Issue 696 ---
class CveInsert(BaseModel):
    """CveInsert schema class."""

    cve_uid: Optional[Any]
    cve_name: str
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    vuln_status: Optional[str] = None
    description: Optional[str] = None
    cvss_v2_source: Optional[str] = None
    cvss_v2_type: Optional[str] = None
    cvss_v2_version: Optional[str] = None
    cvss_v2_vector_string: Optional[str] = None
    cvss_v2_base_score: Optional[float] = None
    cvss_v2_base_severity: Optional[str] = None
    cvss_v2_exploitability_score: Optional[float] = None
    cvss_v2_impact_score: Optional[float] = None
    cvss_v3_source: Optional[str] = None
    cvss_v3_type: Optional[str] = None
    cvss_v3_version: Optional[str] = None
    cvss_v3_vector_string: Optional[str] = None
    cvss_v3_base_score: Optional[float] = None
    cvss_v3_base_severity: Optional[str] = None
    cvss_v3_exploitability_score: Optional[float] = None
    cvss_v3_impact_score: Optional[float] = None
    cvss_v4_source: Optional[str] = None
    cvss_v4_type: Optional[str] = None
    cvss_v4_version: Optional[str] = None
    cvss_v4_vector_string: Optional[str] = None
    cvss_v4_base_score: Optional[float] = None
    cvss_v4_base_severity: Optional[str] = None
    cvss_v4_exploitability_score: Optional[float] = None
    cvss_v4_impact_score: Optional[float] = None
    weaknesses: List[str] = []
    reference_urls: List[str] = []
    cpe_list: List[str] = []

    vender_product: Dict[str, List[Tuple]]


# --- NIST CVE endpoint, Issue 696 ---
class GetCveCall(BaseModel):
    """Get CVE Call schema."""

    cve_name: str

    class Config:
        """GetCveCall schema config class."""

        orm_mode = True


class PshttDomainToRun(BaseModel):
    """PshttDomainsToRun schema class."""

    sub_domain_uid: str
    sub_domain: str
    organizations_uid: str
    name: str

    class Config:
        """PshttDomainsToRun config."""

        orm_mode = True
        validate_assignment = True


class PshttDomainToRunTaskResp(BaseModel):
    """PshttDomainsToRunTaskResp schema class."""

    task_id: str
    status: str
    result: Optional[List[PshttDomainToRun]] = None
    error: Optional[str] = None


class PshttDataBase(BaseModel):
    """PshttDataBase schema class."""

    pshtt_results_uid: UUID
    organizations_uid: Optional[Any]
    sub_domain_uid: Optional[Any]
    data_source_uid: Optional[Any]
    sub_domain: str
    date_scanned: str  # date
    base_domain: str
    base_domain_hsts_preloaded: bool
    canonical_url: str
    defaults_to_https: bool
    domain: str
    domain_enforces_https: bool
    domain_supports_https: bool
    domain_uses_strong_hsts: Optional[bool] = None
    downgrades_https: bool
    htss: bool
    hsts_entire_domain: Optional[bool] = None
    hsts_header: str
    hsts_max_age: Optional[float] = None
    hsts_preload_pending: bool
    hsts_preload_ready: bool
    hsts_preloaded: bool
    https_bad_chain: bool
    https_bad_hostname: bool
    https_cert_chain_length = int
    https_client_auth_required: bool
    https_custom_truststore_trusted: bool
    https_expired_cert: bool
    https_full_connection: bool
    https_live: bool
    https_probably_missing_intermediate_cert: bool
    https_publicly_trusted: bool
    https_self_signed_cert: bool
    https_leaf_cert_expiration_date: Optional[date] = None
    https_leaf_cert_issuer: str
    https_leaf_cert_subject: str
    https_root_cert_issuer: str
    ip: str  # Not sure if there is a better type for this
    live: bool
    notes: str
    redirect: bool
    redirect_to: str
    server_header: str
    server_version: str
    strictly_forces_https: bool
    unknown_error: bool
    valid_https: bool
    ep_http_headers: str  # This field type is a guess.
    ep_http_server_header: str
    ep_http_server_version: str
    ep_https_headers: str  # This field type is a guess.
    ep_https_hsts_header: str
    ep_https_server_header: str
    ep_https_server_version: str
    ep_httpswww_headers: str  # This field type is a guess.
    ep_httpswww_hsts_header: str
    ep_httpswww_server_header: str
    ep_httpswww_server_version: str
    ep_httpwww_headers: str  # This field type is a guess.
    ep_httpwww_server_header: str
    ep_httpwww_server_version: str


class PshttInsert(BaseModel):
    """PshttInsert schema class."""

    organizations_uid: Optional[Any]
    sub_domain_uid: Optional[Any]
    sub_domain: str
    date_scanned: str  # date
    base_domain: str
    base_domain_hsts_preloaded: bool
    canonical_url: str
    defaults_to_https: bool
    domain: str
    domain_enforces_https: bool
    domain_supports_https: bool
    domain_uses_strong_hsts: Optional[bool] = None
    downgrades_https: bool
    htss: bool
    hsts_entire_domain: Optional[bool] = None
    hsts_header: Optional[str] = None
    hsts_max_age: Optional[float] = None
    hsts_preload_pending: bool
    hsts_preload_ready: bool
    hsts_preloaded: bool
    https_bad_chain: bool
    https_bad_hostname: bool
    https_cert_chain_length = int
    https_client_auth_required: bool
    https_custom_truststore_trusted: bool
    https_expired_cert: bool
    https_full_connection: bool
    https_live: bool
    https_probably_missing_intermediate_cert: bool
    https_publicly_trusted: bool
    https_self_signed_cert: bool
    https_leaf_cert_expiration_date: Optional[date] = None
    https_leaf_cert_issuer: Optional[str] = None
    https_leaf_cert_subject: Optional[str] = None
    https_root_cert_issuer: Optional[str] = None
    ip: Optional[str] = None  # Not sure if there is a better type for this
    live: bool
    notes: Optional[str] = None
    redirect: bool
    redirect_to: Optional[str] = None
    server_header: Optional[str] = None
    server_version: Optional[str] = None
    strictly_forces_https: bool
    unknown_error: bool
    valid_https: bool
    ep_http_headers: Optional[str] = None  # This field type is a guess.
    ep_http_server_header: Optional[str] = None
    ep_http_server_version: Optional[str] = None
    ep_https_headers: Optional[str] = None  # This field type is a guess.
    ep_https_hsts_header: Optional[str] = None
    ep_https_server_header: Optional[str] = None
    ep_https_server_version: Optional[str] = None
    ep_httpswww_headers: Optional[str] = None  # This field type is a guess.
    ep_httpswww_hsts_header: Optional[str] = None
    ep_httpswww_server_header: Optional[str] = None
    ep_httpswww_server_version: Optional[str] = None
    ep_httpwww_headers: Optional[str] = None  # This field type is a guess.
    ep_httpwww_server_header: Optional[str] = None
    ep_httpwww_server_version: Optional[str] = None


class AlertInput(BaseModel):
    """AlertInput class."""

    org_uid: str
    start_date: str
    end_date: str

    class Config:
        """AlertInput config class."""

        orm_mode = True


# --- get_orgs(), Issue 699 pe-reports ---
# Return full organization table record
class OrganizationsFullTable(BaseModel):
    """OrganizationsFullTable schema class."""

    organizations_uid: Optional[str] = None
    name: Optional[str] = None
    cyhy_db_name: Optional[str] = None
    org_type_uid: Optional[str] = None
    report_on: Optional[bool] = None
    password: Optional[str] = None
    date_first_reported: Optional[str] = None
    parent_org_uid: Optional[str] = None
    premium_report: Optional[bool] = None
    agency_type: Optional[str] = None
    demo: Optional[bool] = None
    scorecard: Optional[bool] = None
    fceb: Optional[bool] = None
    receives_cyhy_report: Optional[bool] = None
    receives_bod_report: Optional[bool] = None
    receives_cybex_report: Optional[bool] = None
    run_scans: Optional[bool] = None
    is_parent: Optional[bool] = None
    ignore_roll_up: Optional[bool] = None
    retired: Optional[bool] = None
    cyhy_period_start: Optional[str] = None
    fceb_child: Optional[bool] = None
    election: Optional[bool] = None
    scorecard_child: Optional[bool] = None
    location_name: Optional[str] = None
    county: Optional[str] = None
    county_fips: Optional[int] = None
    state_abbreviation: Optional[str] = None
    state_fips: Optional[int] = None
    state_name: Optional[str] = None
    country: Optional[str] = None
    country_name: Optional[str] = None

    class Config:
        """OrganizationsFullTable schema config class."""
        
        orm_mode = True


# --- get_data_source_uid(), Issue 700 pe-reports ---
class DataSourceByNameInput(BaseModel):
    """DataSourceByNameInput schema class."""

    name: str

    class Config:
        """DataSourceByNameInput schema config class."""

        orm_mode = True


# --- get_data_source_uid(), Issue 700 pe-reports ---
class DataSourceFullTable(BaseModel):
    """DataSourceFullTable schema class."""

    data_source_uid: str
    name: str
    description: str
    last_run: str

    class Config:
        """DataSourceFullTable schema config class."""

        orm_mode = True


# --- get_breaches(), Issue 701 pe-reports ---
class BreachNamesAndUIDs(BaseModel):
    """BreachNamesAndUIDs schema class."""

    breach_name: str
    credential_breaches_uid: str

    class Config:
        """BreachNamesAndUIDs schema config class."""

        orm_mode = True


# --- getSubdomain(), Issue 702 pe-reports ---
class SubdomainUIDByDomainInput(BaseModel):
    """SubdomainUIDByDomainInput schema class."""

    domain: str

    class Config:
        """SubdomainUIDByDomainInput schema config class."""

        orm_mode = True


# --- getSubdomain(), Issue 702 pe-reports ---
class SubdomainUIDByDomain(BaseModel):
    """SubdomainUIDByDomain schema class."""

    sub_domain_uid: str

    class Config:
        """SubdomainUIDByDomain schema config class."""

        orm_mode = True


# --- org_root_domains(), Issue 703 pe-reports ---
class RootdomainsByOrgUIDInput(BaseModel):
    """RootdomainsByOrgUIDInput schema class."""

    org_uid: str

    class Config:
        """RootdomainsByOrgUIDInput schema config class."""

        orm_mode = True


# --- org_root_domains(), Issue 703 pe-reports ---
class RootDomainsTable(BaseModel):
    """RootDomainsTable schema class."""

    root_domain_uid: Optional[str] = None
    organizations_uid_id: Optional[str] = None
    root_domain: Optional[str] = None
    ip_address: Optional[str] = None
    data_source_uid_id: Optional[str] = None
    enumerate_subs: Optional[bool] = None

    class Config:
        """RootDomainsTable schema config class."""

        orm_mode = True



# --- domain_permu_insert_dnstwist(), Issue 706 pe-reports/005 atc-framework ---
# Insert multiple dnstwist records into the domain_permutations table
class DomainPermuInsertDNSTwist(BaseModel):
    """DomainPermuInsertDNSTwist schema class."""

    organizations_uid: Optional[str] = None
    data_source_uid: Optional[str] = None
    sub_domain_uid: Optional[str] = None
    domain_permutation: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    mail_server: Optional[str] = None
    name_server: Optional[str] = None
    fuzzer: Optional[str] = None
    date_active: Optional[str] = None
    ssdeep_score: Optional[str] = None
    malicious: Optional[bool] = None
    blocklist_attack_count: Optional[int] = None
    blocklist_report_count: Optional[int] = None
    dshield_record_count: Optional[int] = None
    dshield_attack_count: Optional[int] = None

    class Config:
        """DomainPermuInsertDNSTwist schema config class."""

        orm_mode = True


# --- domain_permu_insert_dnstwist(), Issue 706 pe-reports/005 atc-framework ---
# Insert multiple dnstwist records into the domain_permutations table, input
class DomainPermuInsertDNSTwistInput(BaseModel):
    """DomainPermuInsertDNSTwistInput schema class."""

    insert_data: List[DomainPermuInsertDNSTwist]

    class Config:
        """DomainPermuInsertDNSTwistInput schema config class."""

        orm_mode = True


# --- get_root_domains(), Issue 707 pe-reports/006 atc-framework ---
# This function will reuse the schemas from the /rootdomains_by_org_uid endpoint
    

# --- getDataSource(), Issue 708 pe-reports/007 atc-framework ---
# This function will reuse the schemas from the /data_source_by_name endpoint

        
# --- execute_hibp_breach_values(), Issue 709 pe-reports/008 atc-framework ---
# Insert bulk HIBP breach data into credential_breaches table
class CredBreachesHIBPInsert(BaseModel):
    """CredBreachesHIBPInsert schema class."""

    breach_name: Optional[str] = None
    description: Optional[str] = None
    exposed_cred_count: Optional[int] = None
    breach_date: Optional[str] = None
    added_date: Optional[str] = None
    modified_date: Optional[str] = None
    data_classes: Optional[str] = None
    password_included: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_fabricated: Optional[bool] = None
    is_sensitive: Optional[bool] = None
    is_retired: Optional[bool] = None
    is_spam_list: Optional[bool] = None
    data_source_uid: Optional[str] = None

    class Config:
        """CredBreachesHIBPInsert schema config class."""

        orm_mode = True


# --- execute_hibp_breach_values(), Issue 709 pe-reports/008 atc-framework ---
# Insert bulk HIBP breach data into credential_breaches table, input
class CredBreachesHIBPInsertInput(BaseModel):
    """CredBreachesHIBPInsertInput schema class."""

    breach_data: List[CredBreachesHIBPInsert]

    class Config:
        """CredBreachesHIBPInsertInput schema config class."""

        orm_mode = True


# --- execute_hibp_email_values(), Issue 710 pe-reports/009 atc-framework ---
# Insert bulk HIBP credential data into credential_exposures table
class CredExpHIBPInsert(BaseModel):
    """CredExpHIBPInsert schema class."""

    email: Optional[str] = None
    organizations_uid: Optional[str] = None
    root_domain: Optional[str] = None
    sub_domain: Optional[str] = None
    modified_date: Optional[str] = None
    breach_name: Optional[str] = None
    credential_breaches_uid: Optional[str] = None
    data_source_uid: Optional[str] = None
    name: Optional[str] = None

    class Config:
        """CredExpHIBPInsert schema config class."""

        orm_mode = True


# --- execute_hibp_email_values(), Issue 710 pe-reports/009 atc-framework ---
# Insert bulk IntelX credential data into credential_exposures table, input
class CredExpHIBPInsertInput(BaseModel):
    """CredExpHIBPInsertInput schema class."""

    exp_data: List[CredExpHIBPInsert]

    class Config:
        """CredExpHIBPInsertInput schema config class."""

        orm_mode = True
    

# --- get_breach_uids(), Issue 010 atc-framework ---
# Retrieve all breach names and uids
class BreachUIDs(BaseModel):
    """BreachUIDs schema class."""

    breach_name: Optional[str] = None
    credential_breaches_uid: Optional[str] = None

    class Config:
        """BreachUIDs schema config class."""

        orm_mode = True


# --- query_orgs(), Issue 011 atc-framework ---
# Reuses OrganizationsFullTable schema
        

# --- query_PE_subs(), Issue 012 atc-framework ---
class SubdomainsByOrgUIDInput(BaseModel):
    """SubdomainsByOrgUIDInput schema class."""

    org_uid: str

    class Config:
        """SubdomainsByOrgUIDInput schema config class."""

        orm_mode = True


# --- query_PE_subs(), Issue 012 atc-framework ---
class SubdomainsByOrgUID(BaseModel):
    """SubdomainsByOrgUID schema class."""

    sub_domain: Optional[str] = None
    root_domain: Optional[str] = None

    class Config:
        """SubdomainsByOrgUID schema config class."""

        orm_mode = True
        

# --- insert_shodan_assets(), Issue 016 atc-framework ---
# Insert bulk Shodan data into shodan_assets table
class ShodanAssetsInsert(BaseModel):
    """ShodanAssetsInsert schema class."""

    email: Optional[str] = None
    organizations_uid: Optional[str] = None
    root_domain: Optional[str] = None
    sub_domain: Optional[str] = None
    modified_date: Optional[str] = None
    breach_name: Optional[str] = None
    credential_breaches_uid: Optional[str] = None
    data_source_uid: Optional[str] = None
    name: Optional[str] = None

    class Config:
        """ShodanAssetsInsert schema config class."""

        orm_mode = True


# --- insert_shodan_assets(), Issue 016 atc-framework ---
# Insert bulk Shodan data into shodan_assets table, input
class ShodanAssetsInsertInput(BaseModel):
    """ShodanAssetsInsertInput schema class."""

    asset_data: List[ShodanAssetsInsert]

    class Config:
        """ShodanAssetsInsertInput schema config class."""

        orm_mode = True


# --- insert_shodan_vulns(), Issue 017 atc-framework ---
# Insert bulk Shodan data into shodan_vulns table
class ShodanVulnsInsert(BaseModel):
    """ShodanVulnsInsert schema class."""

    email: Optional[str] = None
    organizations_uid: Optional[str] = None
    root_domain: Optional[str] = None
    sub_domain: Optional[str] = None
    modified_date: Optional[str] = None
    breach_name: Optional[str] = None
    credential_breaches_uid: Optional[str] = None
    data_source_uid: Optional[str] = None
    name: Optional[str] = None

    class Config:
        """ShodanVulnsInsert schema config class."""

        orm_mode = True


# --- insert_shodan_vulns(), Issue 017 atc-framework ---
# Insert bulk Shodan data into shodan_vulns table, input
class ShodanVulnsInsertInput(BaseModel):
    """ShodanVulnsInsertInput schema class."""

    vulns_data: List[ShodanVulnsInsert]

    class Config:
        """ShodanVulnsInsertInput schema config class."""

        orm_mode = True


# --- get_demo_orgs(), Issue 018 atc-framework ---
# Reuses OrganizationsFullTable schema