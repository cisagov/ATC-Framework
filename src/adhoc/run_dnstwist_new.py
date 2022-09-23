"""Use DNS twist to fuzz domain names and cross check with a blacklist."""
# Standard Python Libraries
import datetime
from ipaddress import ip_address
import json
import logging
import traceback

# Third-Party Libraries
from data.config import config
from data.run import query_orgs_rev
import dnstwist
import dshield
import pandas as pd
import psycopg2
import psycopg2.extras as extras
import requests

date = datetime.datetime.now().strftime("%Y-%m-%d")

logging.basicConfig(
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level=logging.INFO,
)


def query_db(conn, query, args=(), one=False):
    """Query the database."""
    cur = conn.cursor()
    cur.execute(query, args)
    r = [
        {cur.description[i][0]: value for i, value in enumerate(row)}
        for row in cur.fetchall()
    ]

    return (r[0] if r else None) if one else r


def getSubdomain(conn, domain):
    """Get subdomains given a domain from the databases."""
    cur = conn.cursor()
    sql = """SELECT * FROM sub_domains sd
        WHERE sd.sub_domain = %(domain)s"""
    cur.execute(sql, {"domain": domain})
    sub = cur.fetchone()
    cur.close()
    return sub


def getRootdomain(conn, domain):
    """Get root domain given domain from the database."""
    cur = conn.cursor()
    sql = """SELECT * FROM root_domains rd
        WHERE rd.root_domain = '%(domain)s'"""
    cur.execute(sql, {"domain": domain})
    root = cur.fetchone()
    cur.close()
    return root


def addRootdomain(conn, root_domain, pe_org_uid, source_uid, org_name):
    """Add a root domain into the database."""
    # ip_address = str(socket.gethostbyname(root_domain))
    sql = """insert into root_domains(root_domain, organizations_uid, organization_name, data_source_uid, ip_address)
            values ('%(root_domain)s', '%(pe_org_uid)s', '%(org_name)s', '%(source_uid)s', '%(ip_address)s');"""
    cur = conn.cursor()
    cur.execute(
        sql,
        {
            "domain": root_domain,
            "pe_org_uid": pe_org_uid,
            "org_name": org_name,
            "source_uid": source_uid,
            "ip_address": ip_address,
        },
    )
    conn.commit()
    cur.close()
    logging.info("Success adding root domain, %(root_domain)s, to root domain table.")


def addSubdomain(conn, domain, pe_org_uid, org_name):
    """Add a subdomain into the database."""
    root_domain = domain.split(".")[-2:]
    root_domain = ".".join(root_domain)
    cur = conn.cursor()
    cur.callproc(
        "insert_sub_domain", (domain, pe_org_uid, "findomain", root_domain, None)
    )
    logging.info("Success adding domain, %(domain)s, to subdomains table.")


def getDataSource(conn, source):
    """Get datasource information from a database."""
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name=%(s)s"""
    cur.execute(sql, {"s": source})
    source = cur.fetchone()
    cur.close()
    return source

    # cur = conn.cursor()
    # sql = f"""SELECT * FROM data_source WHERE name={source}"""
    # cur.execute(sql)
    # source = cur.fetchone()
    # cur.close()
    # return source


def org_root_domains(conn, org_uid):
    """Get from database given the org_uid."""
    sql = """
        select * from root_domains rd
        where rd.organizations_uid = %(org_id)s;
    """
    df = pd.read_sql_query(sql, conn, params={"org_id": org_uid})
    return df


logging.info("wheres the logging man")
"""Connect to PostgreSQL database."""
try:
    params = config()
    PE_conn = psycopg2.connect(**params)
except Exception:
    logging.error("There was a problem logging into the psycopg database")

# instead of importing run .py, lookover config.py and implement steakholder/views style

source_uid = getDataSource(PE_conn, "DNSTwist")[0]
logging.info("source_uid")
logging.info(source_uid)

""" Get P&E Orgs """
orgs = query_orgs_rev()
logging.info(orgs["name"])

failures = []
for i, row in orgs.iterrows():
    pe_org_uid = row["organizations_uid"]
    org_name = row["name"]

    if org_name not in ["National Institute of Standards and Technology"]:
        continue

    logging.info(pe_org_uid)
    logging.info(org_name)

    """Collect DNSTwist data from Crossfeed"""
    try:
        # Get root domains
        rd_df = org_root_domains(PE_conn, pe_org_uid)
        logging.info(rd_df)
        domain_list = []
        perm_list = []
        for i, row in rd_df.iterrows():
            root_domain = row["root_domain"]
            if root_domain == "Null_Root":
                continue
            logging.info(row["root_domain"])

            # Run dnstwist on each root domain
            dnstwist_result = dnstwist.run(
                registered=True,
                tld="/var/www/pe-reports/src/adhoc/common_tlds.dict",
                format="json",
                threads=8,
                domain=root_domain,
            )

            finalorglist = dnstwist_result + []

            for dom in dnstwist_result:
                if ("tld-swap" not in dom["fuzzer"]) and (
                    "original" not in dom["fuzzer"]
                ):
                    logging.info(dom["domain"])
                    secondlist = dnstwist.run(
                        registered=True,
                        tld="common_tlds.dict",
                        format="json",
                        threads=8,
                        domain=dom["domain"],
                    )
                    finalorglist += secondlist

            logging.debug(finalorglist)

            # Get subdomain uid
            sub_domain = root_domain
            logging.info(sub_domain)
            try:
                sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]
                logging.info(sub_domain_uid)
            except Exception:
                # TODO Issue #265 implement custom Exceptions
                logging.info("Unable to get sub domain uid", "warning")
                # Add and then get it
                addSubdomain(PE_conn, sub_domain, pe_org_uid, org_name)
                sub_domain_uid = getSubdomain(PE_conn, sub_domain)[0]

            for dom in finalorglist:
                malicious = False
                attacks = 0
                reports = 0
                if "original" in dom["fuzzer"]:
                    logging.info("original")
                    logging.info(dom["fuzzer"])
                    continue
                if "dns_a" not in dom:
                    continue
                else:
                    logging.info(str(dom["dns_a"][0]))
                    # check IP in Blocklist API
                    response = requests.get(
                        "http://api.blocklist.de/api.php?ip=" + str(dom["dns_a"][0])
                    ).content

                    if str(response) != "b'attacks: 0<br />reports: 0<br />'":
                        malicious = True
                        attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                        reports = int(str(response).split("reports: ")[1].split("<")[0])

                    # check dns-a record in DSheild API
                    if str(dom["dns_a"][0]) == "!ServFail":
                        continue

                    results = dshield.ip(
                        str(dom["dns_a"][0]), return_format=dshield.JSON
                    )
                    results = json.loads(results)
                    try:
                        threats = results["ip"]["threatfeeds"]
                        attacks = results["ip"]["attacks"]
                        attacks = int(0 if attacks is None else attacks)
                        malicious = True
                        dshield_attacks = attacks
                        dshield_count = len(threats)
                    except KeyError:
                        dshield_attacks = 0
                        dshield_count = 0

                if "ssdeep_score" not in dom:
                    dom["ssdeep_score"] = ""
                if "dns_mx" not in dom:
                    dom["dns_mx"] = [""]
                if "dns_ns" not in dom:
                    dom["dns_ns"] = [""]
                if "dns_aaaa" not in dom:
                    dom["dns_aaaa"] = [""]
                else:
                    logging.info(str(dom["dns_aaaa"][0]))
                    # check IP in Blocklist API
                    response = requests.get(
                        "http://api.blocklist.de/api.php?ip=" + str(dom["dns_aaaa"][0])
                    ).content
                    if str(response) != "b'attacks: 0<br />reports: 0<br />'":
                        malicious = True
                        attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                        reports = int(str(response).split("reports: ")[1].split("<")[0])

                    # check dns-a record in DSheild API
                    if str(dom["dns_aaaa"][0]) == "!ServFail":
                        continue
                    results = dshield.ip(
                        str(dom["dns_aaaa"][0]), return_format=dshield.JSON
                    )
                    results = json.loads(results)

                    try:
                        threats = results["ip"]["threatfeeds"]
                        attacks = results["ip"]["attacks"]
                        attacks = int(0 if attacks is None else attacks)
                        malicious = True
                        dshield_attacks = attacks
                        dshield_count = len(threats)
                    except KeyError:
                        dshield_attacks = 0
                        dshield_count = 0

                # Ignore duplicates
                permutation = dom["domain"]
                logging.info(permutation)
                if permutation in perm_list:
                    continue
                else:
                    perm_list.append(permutation)

                domain_dict = {
                    "organizations_uid": pe_org_uid,
                    "data_source_uid": source_uid,
                    "sub_domain_uid": sub_domain_uid,
                    "domain_permutation": dom["domain"],
                    "ipv4": dom["dns_a"][0],
                    "ipv6": dom["dns_aaaa"][0],
                    "mail_server": dom["dns_mx"][0],
                    "name_server": dom["dns_ns"][0],
                    "fuzzer": dom["fuzzer"],
                    "date_active": date,
                    "ssdeep_score": dom["ssdeep_score"],
                    "malicious": malicious,
                    "blocklist_attack_count": attacks,
                    "blocklist_report_count": reports,
                    "dshield_record_count": dshield_count,
                    "dshield_attack_count": dshield_attacks,
                }
                domain_list.append(domain_dict)
                logging.info(domain_list)
    except Exception:
        # TODO Issue #265 create custom Exceptions
        logging.info("Failed selecting DNSTwist data.", "Warning")
        failures.append(org_name)
        logging.info(traceback.format_exc())
    """Insert cleaned data into PE database."""
    try:
        cursor = PE_conn.cursor()
        try:
            columns = domain_list[0].keys()
        except Exception:
            logging.critical("No data in the domain list.")
            failures.append(org_name)
            continue
        table = "domain_permutations"
        sql = """INSERT INTO {}({}) VALUES %s
        ON CONFLICT (domain_permutation,organizations_uid)
        DO UPDATE SET malicious = EXCLUDED.malicious,
            blocklist_attack_count = EXCLUDED.blocklist_attack_count,
            blocklist_report_count = EXCLUDED.blocklist_report_count,
            dshield_record_count = EXCLUDED.dshield_record_count,
            dshield_attack_count = EXCLUDED.dshield_attack_count,
            data_source_uid = EXCLUDED.data_source_uid,
            date_active = EXCLUDED.date_active;"""

        values = [[value for value in dict.values()] for dict in domain_list]
        extras.execute_values(
            cursor,
            sql.format(
                table,
                ",".join(columns),
            ),
            values,
        )
        PE_conn.commit()
        logging.info("Data inserted using execute_values() successfully..")

    except Exception:
        # TODO Issue #265 create custom Exceptions
        logging.info("Failure inserting data into database.")
        failures.append(org_name)
        logging.info(traceback.format_exc())

if failures != []:
    logging.error("These orgs failed:")
    logging.error(failures)

PE_conn.close()
