# ATC-Framework #

[![GitHub Build Status](https://github.com/cisagov/ATC-Framework/workflows/build/badge.svg)](https://github.com/cisagov/ATC-Framework/actions)
[![CodeQL](https://github.com/cisagov/ATC-Framework/workflows/CodeQL/badge.svg)](https://github.com/cisagov/ATC-Framework/actions/workflows/codeql-analysis.yml)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/ATC-Framework/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/ATC-Framework?branch=develop)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/ATC-Framework/develop/badge.svg)](https://snyk.io/test/github/cisagov/ATC-Framework)

This package is used to generate and deliver CISA Posture & Exposure Reports
(P&E Reports). Reports are delivered by email and include an encrypted PDF
attachment with a series of embedded raw-data files of the collected materials.
The reports are delivered in a two step process. First the `pe_reports` module
collects the raw data and creates the encrypted PDFs. The `pe_mailer` then
securely delivers the content.

Topics of interest include *Exposed Credentials, Domain Masquerading, Malware,
Inferred Vulnerabilities and the Dark Web*. The data collected for the reports
is gathered on the 1st and 15th of each month.

## Requirements ##

- [Python Environment](CONTRIBUTING.md#creating-the-python-virtual-environment)

- [cisagov MongoDB](https://github.com/cisagov/mongo-db-from-config)

- [cisagov AWS SES](https://github.com/cisagov/cool-dns-cyber.dhs.gov)

## Installation ##

- `git clone https://github.com/cisagov/pe-reports.git`

- `pip install -e .`

## Create P&E Reports ##

- Configure [cisagov MongoDB connection](https://github.com/cisagov/mongo-db-from-config)

```console
Usage:
  pe-reports REPORT_DATE DATA_DIRECTORY OUTPUT_DIRECTORY [--log-level=LEVEL]

Arguments:
  REPORT_DATE                   Date of the report, format YYYY-MM-DD.
  OUTPUT_DIRECTORY              The directory where the final PDF reports should be saved.
Options:
  -h --help                     Show this message.
  -v --version                  Show version information.
  --log-level=LEVEL             If specified, then the log level will be set to
                                the specified value.  Valid values are "debug", "info",
                                "warning", "error", and "critical". [default: info]
```

## Deliver P&E Reports ##

- Configure [cisagov MongoDB connection](https://github.com/cisagov/mongo-db-from-config)

- Load an AWS profile that assumes [this role](https://github.com/cisagov/cool-dns-cyber.dhs.gov/blob/develop/sessendemail_rolerole.tf#L33-L39)

```console
Usage:
  pe-mailer [--pe-report-dir=DIRECTORY] [--db-creds-file=FILENAME] [--log-level=LEVEL]

Arguments:
  -p --pe-report-dir=DIRECTORY  Directory containing the pe-reports output.
  -c --db-creds-file=FILENAME   A YAML file containing the Cyber
                                Hygiene database credentials.
                                [default: /secrets/database_creds.yml]
Options:
  -h --help                     Show this message.
  -v --version                  Show version information.
  -s --summary-to=EMAILS        A comma-separated list of email addresses
                                to which the summary statistics should be
                                sent at the end of the run.  If not
                                specified then no summary will be sent.
  -t --test_emails=EMAILS       A comma-separated list of email addresses
                                to which to test email send process. If not
                                specified then no test will be sent.
  -l --log-level=LEVEL          If specified, then the log level will be set to
                                the specified value.  Valid values are "debug", "info",
                                "warning", "error", and "critical". [default: info]
```

## Database backup/restore ##

Follow the instructions below to backup the P&E database instance and restore locally.

In the P&E database environment:

- Pull the latest repository
- If necessary, edit ./src/pe_reports/pe_db/pg_backup.sh and replace the
default output path ($PWD) with your preferred output path.
- Open terminal and run:
`bash ./src/pe_reports/pe_db/pg_backup.sh`
- Export resulting .zip file

In your local environment:

- Pull the latest repository
- If necessary, edit ./src/pe_reports/pe_db/pg_restore.sh and replace
the default path to the backup files ($PWD) with your preferred path.
- Start local postgres
- Open terminal and run:
`bash ./src/pe_reports/pe_db/pg_restore.sh`

## Collect P&E Source Data ##

- Add database and data source credentials to src/pe_reports/data/config.ini

```console
Usage:
  pe-source DATA_SOURCE [--log-level=LEVEL] [--orgs=ORG_LIST] [--cybersix-methods=METHODS]

Arguments:
  DATA_SOURCE                       Source to collect data from. Valid values are "cybersixgill",
                                    "dnstwist", "hibp", and "shodan".
Options:
  -h --help                         Show this message.
  -v --version                      Show version information.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
  -o --orgs=ORG_LIST                A comma-separated list of orgs to collect data for.
                                    If not specified, data will be collected for all
                                    orgs in the pe database. Orgs in the list must match the
                                    IDs in the cyhy-db. E.g. DHS,DHS_ICE,DOC
                                    [default: all]
  -csg --cybersix-methods=METHODS   A comma-separated list of cybersixgill methods.
                                    If not specified, all will run. Valid values are "alerts",
                                    "credentials", "mentions", "topCVEs". E.g. alerts,mentions.
                                    [default: all]
```

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and copyright
and related rights in the work worldwide are waived through the
[CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0 dedication.
By submitting a pull request, you are agreeing to comply with this waiver
of copyright interest.
