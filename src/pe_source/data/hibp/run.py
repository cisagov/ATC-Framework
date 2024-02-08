"""Database queries."""
# Standard Python Libraries
import sys

# Third-Party Libraries
from data.hibp.config import config
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
import psycopg2.extras as extras

CONN_PARAMS_DIC = config()


def show_psycopg2_exception(err):
    """Error handleing for postgres issues."""
    err_type, traceback = sys.exc_info()
    line_n = traceback.tb_lineno
    print("\npsycopg2 ERROR:", err, "on line number:", line_n)
    print("psycopg2 traceback:", traceback, "-- type:", err_type)
    print("\nextensions.Diagnostics:", err)
    print("pgerror:", err)
    print("pgcode:", err, "\n")


def connect(thread):
    """Connect to postgres database."""
    conn = None
    try:
        conn = psycopg2.connect(**CONN_PARAMS_DIC)
    except OperationalError as err:
        show_psycopg2_exception(err)
        conn = None
    return conn


def close(conn):
    """Close connection."""
    conn.close()
    return


def execute_values(conn, dataframe, table, except_condition=";"):
    """Insert into datafame."""
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = "INSERT INTO {}({}) VALUES %s"
    sql = sql + except_condition
    cursor = conn.cursor()
    try:
        extras.execute_values(cursor, sql.format(table, cols), tpls)
        conn.commit()
        print("Data inserted using execute_values() successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cursor.close()


def query_values(conn, table, where=";"):
    """Insert of a datafame."""
    sql = "SELECT * FROM {}"
    sql = sql + where
    # try just pandas... pd..read_sql_query(sql, conn)
    df = pd.read_sql_query(sql.format(table), conn)
    conn.close()
    return df


def query_orgs(thread):
    """Query orgs."""
    conn = connect(thread)
    orgs = query_values(conn, "organizations", " WHERE report_on is True;")
    close(conn)
    print(orgs)
    return orgs


def query_roots(conn, org_uid):
    """Insert into datafame."""
    sql = "SELECT * FROM root_domains WHERE organizations_uid = '{}'"
    # try just pandas... pd..read_sql_query(sql, conn)
    df = pd.read_sql_query(sql.format(org_uid), conn)
    return df


def query_null_roots(conn, org_uid):
    """Insert into datafame."""
    sql = "SELECT * FROM root_domains WHERE root_domain = 'Null_Root'"
    # try just pandas... pd..read_sql_query(sql, conn)
    df = pd.read_sql_query(sql, conn)
    return df


def execute_hibp_breach_values(conn, dataframe, table):
    """Insert into datafame."""
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name)
    DO UPDATE SET modified_date = EXCLUDED.modified_date;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            sql.format(
                table,
                cols,
            ),
            tpls,
        )
        conn.commit()
        print("Data inserted using execute_values() successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cursor.close()


def execute_hibp_emails_values(conn, dataframe, table):
    """Insert into datafame."""
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (email, breach_name)
    DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            sql.format(
                table,
                cols,
            ),
            tpls,
        )
        conn.commit()
        print("Data inserted using execute_values() successfully..")
    except (Exception, psycopg2.DatabaseError) as err:
        show_psycopg2_exception(err)
        cursor.close()


# No longer in use
def query_null_subs(conn):
    """Insert into datafame."""
    sql = """SELECT o.name, o.organizations_uid, rd.root_domain, rd.root_domain_uid, sd.sub_domain, sd.sub_domain_uid FROM sub_domains as sd
    JOIN root_domains as rd ON sd.root_domain_uid = rd.root_domain_uid
    JOIN organizations as o ON o.organizations_uid = rd.organizations_uid
    WHERE sub_domain = 'Null_Sub'"""
    # try just pandas... pd..read_sql_query(sql, conn)
    df = pd.read_sql_query(sql, conn)
    return df


def execute_shodan_data(dataframe, table, thread, org_name, failed):
    """Insert shodan data into db."""
    conn = connect(thread)
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (organizations_uid, ip, port, protocol, timestamp)
    DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            sql.format(
                table,
                cols,
            ),
            tpls,
        )
        conn.commit()
        print(
            f"{thread} Data inserted using execute_values() successfully - {org_name}"
        )
    except Exception as e:
        print(f"{org_name} failed inserting into {table}")
        print(f"{thread} {e} - {org_name}")
        failed.append(f"{org_name} failed inserting into {table}")
        conn.rollback()
        cursor.close()
    cursor.close()
    return failed


def execute_dnsmonitor_data(dataframe, table):
    """Execute dns monitor data."""
    conn = connect("")
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (domain_permutation, organizations_uid)
    DO UPDATE SET ipv4 = EXCLUDED.ipv4,
        ipv6 = EXCLUDED.ipv6,
        date_observed = EXCLUDED.date_observed,
        mail_server = EXCLUDED.mail_server,
        name_server = EXCLUDED.name_server,
        sub_domain_uid = EXCLUDED.sub_domain_uid,
        data_source_uid = EXCLUDED.data_source_uid;"""
    cursor = conn.cursor()
    extras.execute_values(
        cursor,
        sql.format(
            table,
            cols,
        ),
        tpls,
    )
    conn.commit()
    print("DNSMonitor Data inserted using execute_values() successfully..")


def execute_dnsmonitor_alert_data(dataframe, table):
    """Execute alert data."""
    conn = connect("")
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (alert_type, sub_domain_uid, date, new_value)
    DO NOTHING;"""
    cursor = conn.cursor()
    extras.execute_values(
        cursor,
        sql.format(
            table,
            cols,
        ),
        tpls,
    )
    conn.commit()
    print("DNSMonitor Alert Data inserted using execute_values() successfully..")


def query_ips(org_id):
    """Query IPs."""
    conn = connect("")
    sql = """SELECT wa.asset as ip_address
            FROM web_assets wa
            WHERE wa.organizations_uid = '{}'
            and wa.report_on = True
            and wa.asset_type = 'ipv4'
            """
    # to just return ipv4 change last line to the following:
    # and wa.asset_type = 'ipv4'
    df = pd.read_sql(sql.format(org_id), conn)
    conn.close()
    return df


def query_orgs_rev():
    """Query orgs in reverse."""
    conn = connect("")
    sql = "SELECT * FROM organizations WHERE report_on is True;"
    df = pd.read_sql_query(sql, conn)
    close(conn)
    return df


def query_web_assets(conn, org_id):
    """Query web assets."""
    sql = """SELECT o.name, o.organizations_uid, wa.asset_type, wa.asset, wa.ip_type,
    wa.asset_origin, wa.report_on, wa.last_scanned
    FROM web_assets as wa
    JOIN organizations o on o.organizations_uid = wa.organizations_uid
    WHERE wa.report_on = True
    and o.organizations_uid = '{}'
    """
    df = pd.read_sql(sql.format(org_id), conn)

    conn.close()
    return df


# No longer in use
def check_ip(ip):
    """Check IPs."""
    conn = connect("")
    sql = """SELECT wa.asset as ip, o.name as org FROM web_assets wa
    JOIN organizations o on o.organizations_uid = wa.organizations_uid
    WHERE wa.asset = '{}'"""
    df = pd.read_sql_query(sql.format(ip), conn)
    close(conn)
    return df


def getSubdomain(domain):
    """Get subdomain."""
    conn = connect("")
    cur = conn.cursor()
    sql = """SELECT * FROM sub_domains sd
        WHERE sd.sub_domain = '{}'"""
    cur.execute(sql.format(domain))
    sub = cur.fetchone()
    cur.close()
    return sub


def getRootdomain(domain):
    """Get root domain."""
    conn = connect("")
    cur = conn.cursor()
    sql = """SELECT * FROM root_domains rd
        WHERE rd.root_domain = '{}'"""
    cur.execute(sql.format(domain))
    root = cur.fetchone()
    cur.close()
    return root


# ***Scpecifically for DNSMonitor
# TODO: Don't hardcode subdomain uid
def addRootToSubdomain(domain):
    """Add root to subdomain."""
    # TODO: getDataSource()
    root_domain_uid = getRootdomain(domain)[0]
    conn = connect("")
    sql = """insert into sub_domains(sub_domain, root_domain_uid, root_domain, data_source_uid)
            values ('{}', '{}', '{}','f7229dcc-98a9-11ec-a1c4-02589a36c9d7');"""
    cur = conn.cursor()
    cur.execute(sql.format(domain, root_domain_uid, domain))
    conn.commit()
    close(conn)
    print(f"Success adding root domain, {domain}, to subdomains table.")


def getDataSource(source):
    """Get data source."""
    conn = connect("")
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name='{}'"""
    cur.execute(sql.format(source))
    source = cur.fetchone()
    cur.close()
    return source


def insertWASIds(listIds):
    """Insert WAS IDs into database."""
    conn = connect("")
    sql = """INSERT INTO was_map (was_org_id,pe_org_id)
            VALUES ('{}','{}')
            ON CONFLICT (was_org_id) DO NOTHING;"""
    sqlNoUUID = """INSERT INTO was_map (was_org_id)
            VALUES ('{}')
            ON CONFLICT (was_org_id) DO NOTHING;"""
    cur = conn.cursor()
    for id in listIds:
        if id[1] == "":
            cur.execute(sqlNoUUID.format(id[0]))
        else:
            cur.execute(sql.format(id[0], id[1]))
    conn.commit()
    close(conn)
    print("Success adding WAS IDs to database.")


def insertFindingData(findingList):
    """Insert finding data into database."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect("")
    sql = """INSERT INTO was_findings (finding_uid, finding_type, webapp_id, was_org_id, owasp_category, severity, times_detected, base_score, temporal_score, fstatus, last_detected, first_detected, potential)
            VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}')
            ON CONFLICT (finding_uid) DO UPDATE
            SET is_remidiated = CASE
                WHEN was_findings.fstatus != 'FIXED' AND excluded.fstatus = 'FIXED' THEN TRUE
                ELSE was_findings.is_remidiated
            END,
            fstatus = excluded.fstatus,
            times_detected = excluded.times_detected,
            last_detected = excluded.last_detected,
            potential = excluded.potential;"""
    cur = conn.cursor()
    for finding in findingList:
        try:
            cur.execute(
                sql.format(
                    finding["finding_uid"],
                    finding["finding_type"],
                    finding["webapp_id"],
                    finding["was_org_id"],
                    finding["owasp_category"],
                    finding["severity"],
                    finding["times_detected"],
                    finding["base_score"],
                    finding["temporal_score"],
                    finding["fstatus"],
                    finding["last_detected"],
                    finding["first_detected"],
                    finding["potential"],
                )
            )
        except KeyError:
            print("KeyError")
            print(finding)
    conn.commit()
    close(conn)
    print("Success adding finding data to database.")


def queryVulnWebAppCount(org_id):
    """Query the amount of webapps with vulnerabilities."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect("")
    sql = """   SELECT webapp_id FROM was_findings
                WHERE was_org_id = '{}'
                AND
                (
                    fstatus = 'ACTIVE'
                    OR fstatus = 'NEW'
                    OR fstatus = 'REOPENED'
                );
        """
    df = pd.read_sql_query(sql.format(org_id), conn)
    webIdsList = df["webapp_id"].values.tolist()
    close(conn)
    return len(set(webIdsList))


def queryWASOrgList():
    """Query the list of WAS orgs."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect("")
    sql = """SELECT was_org_id FROM was_map"""
    df = pd.read_sql_query(sql, conn)
    orgList = df["was_org_id"].values.tolist()
    close(conn)
    return orgList


def getPreviousFindings(org_id, monthsAgo):
    """Get findings for specific time period in months."""
    conn = connect("")
    cur = conn.cursor()
    sql = """   SELECT * FROM was_findings
                WHERE was_org_id = '{}'
                AND last_detected >= date_trunc('month', now() - interval '{} month')
                AND last_detected < date_trunc('month', now() - interval '{} month');
                """
    cur.execute(sql.format(org_id, monthsAgo, monthsAgo - 1), conn)
    ret = cur.fetchall()
    cur.close()
    close(conn)
    return ret


def getPreviousFindingsHistorical(org_id, monthsAgo):
    """Get findings for specific time period in months."""
    conn = connect("")
    cur = conn.cursor()
    sql = """   SELECT * FROM was_findings
                WHERE was_org_id = '{}';
                """
    cur.execute(sql.format(org_id, monthsAgo - 1, monthsAgo), conn)
    ret = cur.fetchall()
    cur.close()
    close(conn)
    return ret


def getPotential(org_id):
    """Get findings for specific time period in months."""
    conn = connect("")
    cur = conn.cursor()
    sql = """   SELECT COUNT(*) FROM was_findings
                WHERE was_org_id = '{}' AND potential IS TRUE;
                """
    cur.execute(sql.format(org_id), conn)
    ret = cur.fetchall()
    cur.close()
    close(conn)
    return ret


def queryVulnCountSeverity(org_id, severity):
    """Query the amount of webapps with vulnerabilities."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect("")
    sql = """   SELECT webapp_id FROM was_findings
                WHERE was_org_id = '{}'
                AND severity = '{}'
                AND
                (
                    fstatus = 'ACTIVE'
                    OR fstatus = 'NEW'
                    OR fstatus = 'REOPENED'
                );
        """
    df = pd.read_sql_query(sql.format(org_id, severity), conn)
    webIdsList = df["webapp_id"].values.tolist()
    close(conn)
    return len(webIdsList)


def queryVulnCountAll(org_id):
    """Query the amount of webapps with vulnerabilities."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect("")
    sql = """   SELECT webapp_id FROM was_findings
                WHERE was_org_id = '{}'
                AND
                (
                    fstatus = 'ACTIVE'
                    OR fstatus = 'NEW'
                    OR fstatus = 'REOPENED'
                );
        """
    df = pd.read_sql_query(sql.format(org_id), conn)
    webIdsList = df["webapp_id"].values.tolist()
    close(conn)
    return len(webIdsList)


def getPEuuid(org_id):
    """Query the org uuid given a certain cyhy db name."""
    conn = connect("")
    sql = """SELECT organizations_uid FROM organizations WHERE cyhy_db_name = '{}'"""
    cur = conn.cursor()
    cur.execute(sql.format(org_id))
    ret = cur.fetchone()[0]
    close(conn)
    return ret


def insertWASVulnData(data):
    """Insert WAS vulnerability data into database."""
    conn = connect("")
    cur = conn.cursor()
    sql = """   INSERT INTO was_history (was_org_ID,date_scanned,vuln_cnt,vuln_webapp_cnt,web_app_cnt,high_rem_time,crit_rem_time,report_period,high_vuln_cnt,crit_vuln_cnt,crit_rem_cnt,high_rem_cnt,total_potential)
                VALUES ('{}','{}',{},{},{}, (CASE WHEN {} = 0 THEN NULL ELSE {} END), (CASE WHEN {} = 0 THEN NULL ELSE {} END),'{}',{},{},{},{},{}) """
    cur.execute(
        sql.format(
            data["was_org_id"],
            data["date_scanned"],
            data["vuln_cnt"],
            data["vuln_webapp_cnt"],
            data["web_app_cnt"],
            data["high_rem_time"],
            data["high_rem_time"],
            data["crit_rem_time"],
            data["crit_rem_time"],
            data["report_period"],
            data["high_vuln_cnt"],
            data["crit_vuln_cnt"],
            data["high_rem_cnt"],
            data["crit_rem_cnt"],
            data["total_potential"],
        )
    )
    conn.commit()
    close(conn)
    print("Success adding finding data to database.")
