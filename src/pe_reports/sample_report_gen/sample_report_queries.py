"""All SQL database queries needed for the sample report process."""

# Imports
import datetime
import hashlib
import logging
import pandas as pd
import psycopg2
import random

# Setup Logging
main_log = logging.getLogger(__name__)


# --- Queries to create sample organization/data ---

def create_sample_org(conn, date_obj):
    """Insert fake organization into the DB."""
    main_log.info("Inserting placeholder organization into database...")
    # Build query
    date = date_obj.strftime("%Y-%m-%d")
    timestamp = date_obj.strftime("%Y-%m-%d %H:%M:%S")
    sql = f"""
        INSERT INTO
            organizations (
                name,
                cyhy_db_name,
                report_on,
                password,
                date_first_reported,
                premium_report,
                agency_type,
                demo,
                scorecard,
                fceb,
                receives_cyhy_report,
                receives_bod_report,
                receives_cybex_report,
                run_scans,
                is_parent,
                ignore_roll_up,
                retired,
                cyhy_period_start,
                fceb_child,
                election,
                scorecard_child
            )
        VALUES (
            'Sample Organization',
            'SAMPLE_ORG',
            True,
            PGP_SYM_ENCRYPT('password123', 'SnowyWaffle&ToastyPancake')::text,
            '{date}',
            True,
            'FEDERAL',
            False,
            True,
            True,
            True,
            True,
            True,
            False,
            False,
            False,
            False,
            '{timestamp}',
            False,
            False,
            False
        )
        ON CONFLICT (cyhy_db_name)
        DO NOTHING
        """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample organization inserted successfully using create_sample_org()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample org info
    sql = "SELECT * FROM organizations WHERE cyhy_db_name = 'SAMPLE_ORG'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_rootdomain(conn, org_id):
    """Insert fake rootdomain data into the DB."""
    main_log.info("Inserting placeholder rootdomain data into database...")
    # Build query
    sql = f"""
        INSERT INTO
            root_domains (
                organizations_uid,
                root_domain,
                data_source_uid,
                enumerate_subs
            )
        VALUES (
            '{org_id}',
            'sample_root1.gov',
            'f7229dcc-98a9-11ec-a1c4-02589a36c9d7',
            True
        )
        ON CONFLICT (root_domain, organizations_uid)
        DO NOTHING
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample rootdomain data inserted successfully using create_sample_rootdomain()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample rootdomain info
    sql = f"SELECT * FROM root_domains WHERE organizations_uid = '{org_id}'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_subdomain(conn, date_obj, root_id):
    """Insert fake subdomain data into the DB."""
    main_log.info("Inserting placeholder subdomain data into database...")
    date = date_obj.strftime("%Y-%m-%d")
    # Build query
    insert_values = ""
    for i in range(1,6):
        insert_values += f"('sample_sub{i}.sample_root1.gov','{root_id}','8049f718-981d-11ec-a105-02589a36c9d7','{date}','{date}',True,True),\n"
    insert_values = insert_values[:-2]
    sql = f"""
        INSERT INTO
            sub_domains (
                sub_domain,
                root_domain_uid,
                data_source_uid,
                first_seen,
                last_seen,
                current,
                identified
            )
        VALUES 
            {insert_values}
        ON CONFLICT (sub_domain, root_domain_uid)
        DO NOTHING
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample subdomain data inserted successfully using create_sample_subdomain()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample subdomain info
    sql = f"SELECT * FROM sub_domains WHERE root_domain_uid = '{root_id}'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_cidr(conn, date_obj, org_id):
    """Insert fake CIDR data into the DB."""
    main_log.info("Inserting placeholder CIDR data into database...")
    date = date_obj.strftime("%Y-%m-%d")
    # Build query
    sql = f"""
        INSERT INTO
            cidrs (
                network,
                organizations_uid,
                data_source_uid,
                first_seen,
                last_seen,
                current
            )
        VALUES (
            '192.0.2.0/29',
            '{org_id}',
            '68550c2c-98c9-11ec-a1c5-02589a36c9d7',
            '{date}',
            '{date}',
            True
        )
        ON CONFLICT (network, organizations_uid)
        DO NOTHING
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample CIDR data inserted successfully using create_sample_cidr()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample CIDR info
    sql = f"SELECT * FROM cidrs WHERE organizations_uid = '{org_id}'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_ip(conn, date_obj, org_id, cidr_id):
    """Insert fake IP data into the DB."""
    main_log.info("Inserting placeholder IP data into database...")
    date = date_obj.strftime("%Y-%m-%d")
    timestamp = date_obj.strftime("%Y-%m-%d %H:%M:%S")
    # Build query
    insert_values = ""
    for i in range(0,8):
        hash_object = hashlib.sha256(f"192.0.2.{i}".encode("utf-8"))
        ip_hash = hash_object.hexdigest()
        insert_values += f"('{ip_hash}','192.0.2.{i}','{cidr_id}','{timestamp}','{date}','{date}',True,True,'{org_id}'),\n"
    insert_values = insert_values[:-2]
    sql = f"""
        INSERT INTO
            ips (
                ip_hash,
                ip,
                origin_cidr,
                last_reverse_lookup,
                first_seen,
                last_seen,
                current,
                from_cidr,
                organizations_uid
            )
        VALUES 
            {insert_values}
        ON CONFLICT (ip)
        DO NOTHING
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample IP data inserted successfully using create_sample_ip()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample IP info
    sql = f"SELECT * FROM ips WHERE origin_cidr = '{cidr_id}'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_cred_breach(conn, date_obj):
    """Insert fake credential breach data into the DB."""
    main_log.info("Inserting placeholder credential breach data into database...")
    base_date = date_obj - datetime.timedelta(2)
    dates = []
    timestamps = []
    for i in range(0,4):
        curr_week = base_date - datetime.timedelta(7*i)
        dates.append(curr_week.strftime("%Y-%m-%d"))
        timestamps.append(curr_week.strftime("%Y-%m-%d %H:%M:%S"))
    cred_counts_pass = [3, 7, 4, 6]
    cred_counts_nopass = [1, 3, 2, 3]
    # Build query
    insert_values = ""
    breach_ct = 1
    for i in range(0,4):
        # w/ pass
        insert_values += f"('Sample Breach {breach_ct}','This is placeholder credential breach number {breach_ct}',{cred_counts_pass[i]},'{dates[i]}','{timestamps[i]}','{timestamps[i]}',True,'744fb0ec-981d-11ec-a0ff-02589a36c9d7'),\n"
        breach_ct += 1
        # w/o pass
        insert_values += f"('Sample Breach {breach_ct}','This is placeholder credential breach number {breach_ct}',{cred_counts_nopass[i]},'{dates[i]}','{timestamps[i]}','{timestamps[i]}',False,'744fb0ec-981d-11ec-a0ff-02589a36c9d7'),\n"
        breach_ct += 1
    insert_values = insert_values[:-2]
    sql = f"""
        INSERT INTO
            credential_breaches (
                breach_name,
                description,
                exposed_cred_count,
                breach_date,
                added_date,
                modified_date,
                password_included,
                data_source_uid
            )
        VALUES 
            {insert_values}
        ON CONFLICT (breach_name)
        DO NOTHING
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample cred breach data inserted successfully using create_sample_cred_breach()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample cred_breach info
    sql = "SELECT * FROM credential_breaches WHERE breach_name like 'Sample Breach %'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_cred_exp(conn, date_obj, org_id, breach_df):
    """Insert fake credential exposure data into the DB."""
    main_log.info("Inserting placeholder credential exposure data into database...")
    # Build query
    insert_values = ""
    record_ct = 1
    for idx, row in breach_df.iterrows():
        # For each breach
        num_exp = row["exposed_cred_count"] 
        breach_id = row["credential_breaches_uid"]
        breach_name = row["breach_name"]
        breach_date = row["modified_date"]
        pass_incl = row["password_included"]
        for i in range(0, num_exp):
            # Create the appropriate number of cred exposures
            if pass_incl:
                curr_pass = "'password123'"
            else:
                curr_pass = "NULL"
            insert_values += f"('email{record_ct}@sample_sub1.sample_root1.gov','{org_id}','sample_root1.gov','sample_sub1.sample_root1.gov','{breach_name}','{breach_date}','{breach_id}','744fb0ec-981d-11ec-a0ff-02589a36c9d7',{curr_pass},'plain'),\n"
            record_ct += 1
    insert_values = insert_values[:-2]    
    sql = f"""
        INSERT INTO
            credential_exposures (
                email,
                organizations_uid,
                root_domain,
                sub_domain,
                breach_name,
                modified_date,
                credential_breaches_uid,
                data_source_uid,
                password,
                hash_type
            )
        VALUES 
            {insert_values}
        ON CONFLICT (email, breach_name)
        DO NOTHING
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample cred exposure data inserted successfully using create_sample_cred_exp()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample cred_exp info
    sql = f"SELECT * FROM credential_exposures WHERE organizations_uid = '{org_id}'"
    df = pd.read_sql(sql, conn)
    return df



def create_sample_domain_alert(conn, date_obj, sub_ids, org_id):
    """Insert fake domain alert data into the DB."""
    main_log.info("Inserting placeholder domain alert data into database...")
    date = date_obj.strftime("%Y-%m-%d")
    # Build query
    insert_values = ""
    for i in range(1,5):
        rand_desc = random.choice(
            [
                f"The tracked domain sample_sub{i}.sample_root1.gov has a new dnsA record, 123.45.678.91",
                f"The customer domain sample_sub{i}.sample_root1.gov has a different dnsA record, 1.2.3.4 - 10.12.13.14",
            ]
        )
        insert_values += f"('{sub_ids[i-1]}','7cd71c0a-981d-11ec-a103-02589a36c9d7','{org_id}','New Variant Record','{rand_desc}','123.45.678.91','{date}'),\n"
    insert_values = insert_values[:-2]
    sql = f"""
        INSERT INTO
            domain_alerts (
                sub_domain_uid,
                data_source_uid,
                organizations_uid,
                alert_type,
                message,
                new_value,
                date
            )
        VALUES
            {insert_values}
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample domain alert data inserted successfully using create_sample_domain_alert()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample domain alert info
    sql = f"SELECT * FROM domain_alerts WHERE organizations_uid = '{org_id}'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_domain_permu(conn, date_obj, org_id, sub_ids):
    """Insert fake domain permutation (suspected domain) data into the DB."""
    main_log.info("Inserting placeholder domain permutation data into database...")
    date = date_obj.strftime("%Y-%m-%d")
    # Build query
    domain_permus = [
        "sampl.com",
        "sample.cl",
        "sample.vn",
        "sam.ple.com",
        "ample.com",
    ]
    mail_servers = [
        "sample.s.com",
        "sample1.s.com",
        "sample2.s.com",
        "sample3.s.com",
        "sample4.s.com",
    ]
    name_servers = [
        "samp.sample.net",
        "samp1.sample.net",
        "samp2.sample.net",
        "samp3.sample.net",
        "samp4.sample.net",
    ]
    insert_values = ""
    for i in range(1,6):
        insert_values += f"('{org_id}','{domain_permus[i-1]}','1.2.3.4','N/A','{mail_servers[i-1]}','{name_servers[i-1]}','tld-swap','{date}',True,1,2,'7ad1b168-981d-11ec-a102-02589a36c9d7','{sub_ids[i-1]}',3,4,'{date}'),\n"
    insert_values = insert_values[:-2]
    sql = f"""
        INSERT INTO
            domain_permutations (
                organizations_uid,
                domain_permutation,
                ipv4,
                ipv6,
                mail_server,
                name_server,
                fuzzer,
                date_observed,
                malicious,
                blocklist_attack_count,
                blocklist_report_count,
                data_source_uid,
                sub_domain_uid,
                dshield_record_count,
                dshield_attack_count,
                date_active
            )
        VALUES
            {insert_values}
        ON CONFLICT (organizations_uid, domain_permutation)
        DO NOTHING
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample domain permutation data inserted successfully using create_sample_domain_premu()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample domain permutation info
    sql = f"SELECT * FROM domain_permutations WHERE organizations_uid = '{org_id}'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_shodan_vuln(conn, date_obj, org_df, ip_df):
    """Insert fake shodan vulnerability data into the DB."""
    main_log.info("Inserting placeholder shodan vulnerability data into database...")
    timestamp = date_obj.strftime("%Y-%m-%d %H:%M:%S")
    org_id = org_df["organizations_uid"].values[0]
    org_name = org_df["name"].values[0]
    ips = ip_df["ip"].tolist()
    # Build query
    ports = [
        "443",
        "8088",
        "445",
        "21", #
        "110", #
        "3389",
        "80",
        "23",
    ]
    protocols = [
        "http", 
        "telnet",
        "RDP",
        "RDP", #
        "telnet", #
        "RDP",
        "SMB",
        "telnet"
    ]
    types = [
        "Insecure Protocol",
        "Insecure Protocol",
        "Insecure Protocol",
        "Insecure Protocol", #
        "Insecure Protocol", #
        "Pontentially Vulnerable Product",
        "Pontentially Vulnerable Product",
        "Pontentially Vulnerable Product",
    ]
    potential_vulns = [
        "{HTTP}",
        "{TELNET}",
        "{RDP}",
        "{RDP}", #
        "{TELNET}", #
        "{CVE-1234-5678, CVE-9101-1121}",
        "{CVE-1234-5678, CVE-9101-1121, CVE-3141-5161}",
        "{CVE-1234-5678, CVE-9101-1121, CVE-3141-5161, CVE-7181-9202, CVE-1222-3242}",
    ]
    verif_status = [
        "True",
        "True",
        "False",
        "False", #
        "False", #
        "False",
        "False",
        "False",
    ]
    insert_values = ""
    for i in range(1,9):
        insert_values += f"('{org_id}','{org_name}','{ips[i-1]}','{ports[i-1]}','{protocols[i-1]}','{timestamp}','CVE-1234-5678','Sample summary of CVE-1234-5678.','763eb880-981d-11ec-a100-02589a36c9d7','{types[i-1]}','{potential_vulns[i-1]}',{verif_status[i-1]}),\n"
    insert_values = insert_values[:-2]
    sql = f"""
        INSERT INTO
            shodan_vulns (
                organizations_uid,
                organization,
                ip,
                port,
                protocol,
                timestamp,
                cve,
                summary,
                data_source_uid,
                type,
                potential_vulns,
                is_verified
            )
        VALUES
            {insert_values}
        ON CONFLICT (organizations_uid, ip, port, protocol, timestamp)
        DO NOTHING
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample shodan vulnerability data inserted successfully using create_sample_shodan_vuln()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample shodan vuln info
    sql = f"SELECT * FROM shodan_vulns WHERE organizations_uid = '{org_id}'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_shodan_asset(conn, date_obj, org_df, ip_df):
    """Insert fake shodan asset data into the DB."""
    main_log.info("Inserting placeholder shodan asset data into database...")
    timestamp = date_obj.strftime("%Y-%m-%d %H:%M:%S")
    org_id = org_df["organizations_uid"].values[0]
    org_name = org_df["name"].values[0]
    ips = ip_df["ip"].tolist()
    # Build query
    ports = [
        "445",
        "23",
        "80",
        "123",
        "445",
    ]
    protocols = [
        "http", 
        "RDP",
        "telnet",
        "SMB",
        "http",
    ]
    country_codes = [
        "CA",
        "DE",
        "IL",
        "GB",
        "SE",
    ]
    products = [
        "MySQL",
        "CloudFlare",
        "GitLab",
        "MySQL",
        "GitLab"
    ]
    insert_values = ""
    for i in range(0,5):
        insert_values += f"('{org_id}','{org_name}','{ips[i]}','{ports[i]}','{protocols[i]}','{timestamp}','{products[i]}','763eb880-981d-11ec-a100-02589a36c9d7','{country_codes[i]}'),\n"
    insert_values = insert_values[:-2]
    sql = f"""
        INSERT INTO
            shodan_assets (
                organizations_uid,
                organization,
                ip,
                port,
                protocol,
                timestamp,
                product,
                data_source_uid,
                country_code
            )
        VALUES
            {insert_values}
        ON CONFLICT (organizations_uid, ip, port, protocol, timestamp)
        DO NOTHING
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample shodan asset data inserted successfully using create_sample_shodan_asset()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample shodan_asset info
    sql = f"SELECT * FROM shodan_assets WHERE organizations_uid = '{org_id}'"
    df = pd.read_sql(sql, conn)
    return df


def create_sample_mention(conn, date_obj, org_id):
    """Insert fake cybersixgill mention data into the DB."""
    main_log.info("Inserting placeholder cybersixgill mention data into database...")
    # Build query
    base_date = date_obj - datetime.timedelta(2)
    dates = []
    for i in range(0,4):
        curr_week = base_date - datetime.timedelta(7*i)
        dates.append(curr_week.strftime("%Y-%m-%d"))
    mention_counts = [5, 8, 4, 7]
    site_types = [
        "sample_site",
        "forum_sample",
        "market_sample"
    ]
    record_ct = 1
    insert_values = ""
    for week in range(0, 4):
        num_mentions = mention_counts[week]
        curr_date = dates[week]
        # For each preceding week
        for i in range(0, num_mentions):
            # Create the appropriate number of mentions
            rand_grade = random.choice(range(1,11))
            rand_comment_ct = random.choice([3,5,7,11,15])
            insert_values += f"('sample_creator_{record_ct}','{curr_date}','sample_sixgill_id_{record_ct}','{rand_grade}','{site_types[i%3]}','Sample Title {record_ct}','{rand_comment_ct}','{org_id}','744fb0ec-981d-11ec-a0ff-02589a36c9d7'),\n"
            record_ct += 1
    insert_values = insert_values[:-2]
    sql = f"""
        INSERT INTO
            mentions (
                creator,
                date,
                sixgill_mention_id,
                rep_grade,
                site,
                title,
                comments_count,
                organizations_uid,
                data_source_uid
            )
        VALUES
            {insert_values}
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample cybersixgill mention data inserted successfully using create_sample_mention()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample shodan_asset info
    sql = f"SELECT * FROM mentions WHERE organizations_uid = '{org_id}'"
    df = pd.read_sql(sql, conn)
    return df

def create_sample_alert(conn, date_obj, org_id):
    """Insert fake cybersixgill alert data into the DB."""
    main_log.info("Inserting placeholder cybersixgill alert data into database...")
    # Build query
    date = date_obj.strftime("%Y-%m-%d")
    insert_values = ""
    # Add asset alerts
    for i in range(1, 6):
        insert_values += f"('sample_asset_alert_{i}','Content for sample asset alert {i}.','{date}','sample_site_{i}','{{\"Data Leak\"}}','Sample Alert Title','{org_id}','744fb0ec-981d-11ec-a0ff-02589a36c9d7'),\n"
    # Add executive alerts
    for i in range(1, 4):
        insert_values += f"('sample_executive_alert_{i}','Content for sample executive alert {i}.','{date}','sample_site_{i}','{{\"General Mentions\"}}','Organization executive was mentioned on a malicious site','{org_id}','744fb0ec-981d-11ec-a0ff-02589a36c9d7'),\n"
    # Add invite only market alerts
    for i in range(1, 5):
        insert_values += f"('sample_invite_only_market_alert_{i}','Content for sample invite-only market alert {i}.','{date}','market_sample_site_{i}','{{\"Compromised Accounts\"}}','Sample Alert Title','{org_id}','744fb0ec-981d-11ec-a0ff-02589a36c9d7'),\n"
    insert_values = insert_values[:-2]
    sql = f"""
        INSERT INTO
            alerts (
                alert_name,
                content,
                date,
                site,
                threats,
                title,
                organizations_uid,
                data_source_uid
            )
        VALUES
            {insert_values}
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample cybersixgill alert data inserted successfully using create_sample_alert()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()
    # Retrieve new sample shodan_asset info
    sql = f"SELECT * FROM alerts WHERE organizations_uid = '{org_id}'"
    df = pd.read_sql(sql, conn)
    return df


# --- Queries to delete sample organization/data ---
def get_delete_info(conn):
    """Retrieve all info needed for the deletion process."""
    org_sql = f"SELECT * FROM organizations WHERE cyhy_db_name = 'SAMPLE_ORG'"
    org_df = pd.read_sql(org_sql, conn)
    org_id = org_df["organizations_uid"].values[0]
    root_sql = f"SELECT * FROM root_domains WHERE organizations_uid = '{org_id}'"
    root_df = pd.read_sql(root_sql, conn)
    root_id = root_df["root_domain_uid"].values[0]
    cidr_sql = f"SELECT * FROM cidrs WHERE organizations_uid = '{org_id}'"
    cidr_df = pd.read_sql(cidr_sql, conn)
    cidr_id = cidr_df["cidr_uid"].values[0]
    return [org_id, root_id, cidr_id]


def delete_sample_org(conn):
    """Delete sample organization from the DB."""
    main_log.info("Removing placeholder organization from database... (This may take a while)")
    # Build query
    sql = """
        DELETE FROM organizations
        WHERE cyhy_db_name = 'SAMPLE_ORG'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample organization deleted successfully using delete_sample_org()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)
        cursor.close()


def delete_sample_rootdomain(conn, org_id):
    """Delete sample rootdomain data from the DB."""
    main_log.info("Removing placeholder rootdomain data from database...")
    # build query
    sql = f"""
        DELETE FROM root_domains
        WHERE organizations_uid = '{org_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample rootdomain data deleted successfully using delete_sample_rootdomain()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)

    
def delete_sample_subdomain(conn, root_id):
    """Delete sample subdomain data from the DB."""
    main_log.info("Removing placeholder subdomain data from database...")
    # build query
    sql = f"""
        DELETE FROM sub_domains
        WHERE root_domain_uid = '{root_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample subdomain data deleted successfully using delete_sample_subdomain()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)


def delete_sample_cidr(conn, org_id):
    """Delete sample CIDR data from the DB."""
    main_log.info("Removing placeholder CIDR data from database...")
    # build query
    sql = f"""
        DELETE FROM cidrs
        WHERE organizations_uid = '{org_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample CIDR data deleted successfully using delete_sample_cidr()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)


def delete_sample_ip(conn, cidr_id):
    """Delete sample IP data from the DB."""
    main_log.info("Removing placeholder IP data from database...")
    # build query
    sql = f"""
        DELETE FROM ips
        WHERE origin_cidr = '{cidr_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample IP data deleted successfully using delete_sample_ip()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)


def delete_sample_cred_breach(conn):
    """Delete sample credential breach data from the DB."""
    main_log.info("Removing placeholder crdential breach data from database...")
    # build query
    sql = """
        DELETE FROM credential_breaches
        WHERE breach_name LIKE 'Sample Breach %'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample cred breach data deleted successfully using delete_sample_cred_breach()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)


def delete_sample_cred_exp(conn, org_id):
    """Delete sample credential exposure data from the DB."""
    main_log.info("Removing placeholder credential exposure data from database...")
    # build query
    sql = f"""
        DELETE FROM credential_exposures
        WHERE organizations_uid = '{org_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample cred exposure data deleted successfully using delete_sample_cred_exp()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)


def delete_sample_domain_alert(conn, org_id):
    """Delete sample domain alert data from the DB."""
    main_log.info("Removing placeholder domain data from database...")
    # build query
    sql = f"""
        DELETE FROM domain_alerts
        WHERE organizations_uid = '{org_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample domain alert data deleted successfully using delete_sample_domain_alert()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)


def delete_sample_domain_permu(conn, org_id):
    """Delete sample domain permutation data from the DB."""
    main_log.info("Removing placeholder domain permutation from database...")
    # build query
    sql = f"""
        DELETE FROM domain_permutations
        WHERE organizations_uid = '{org_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample domain permutation data deleted successfully using delete_sample_domain_permu()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)


def delete_sample_shodan_vuln(conn, org_id):
    """Delete sample shodan vuln data from the DB."""
    main_log.info("Removing placeholder shodan vulns from database...")
    # build query
    sql = f"""
        DELETE FROM shodan_vulns
        WHERE organizations_uid = '{org_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample shodan vuln data deleted successfully using delete_sample_shodan_vuln()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)


def delete_sample_shodan_asset(conn, org_id):
    """Delete sample shodan asset data from the DB."""
    main_log.info("Removing placeholder shodan assets from database...")
    # build query
    sql = f"""
        DELETE FROM shodan_assets
        WHERE organizations_uid = '{org_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample shodan asset data deleted successfully using delete_sample_shodan_asset()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)

    
def delete_sample_mention(conn, org_id):
    """Delete sample cybersixgill mention data from the DB."""
    main_log.info("Removing placeholder cybersixgill mentions from database...")
    # build query
    sql = f"""
        DELETE FROM mentions
        WHERE organizations_uid = '{org_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample cybersixgill mention data deleted successfully using delete_sample_mention()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)


def delete_sample_alert(conn, org_id):
    """Delete sample cybersixgill alert data from the DB."""
    main_log.info("Removing placeholder cybersixgill alerts from database...")
    # build query
    sql = f"""
        DELETE FROM alerts
        WHERE organizations_uid = '{org_id}'
    """
    # Attempt to execute query
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        main_log.info("Sample cybersixgill alert data deleted successfully using delete_sample_alert()")
    except (Exception, psycopg2.DatabaseError) as err:
        main_log.error("There was a problem with your database query %s", err)