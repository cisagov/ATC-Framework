"""Python scripts to generate PDF outputs of scan data."""

# Imports
# Standard Python Libraries
from hashlib import sha256
import os

# Third-Party Libraries
import demoji
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from reportlab.lib import utils
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.doctemplate import BaseDocTemplate, PageTemplate
from reportlab.platypus.flowables import BalancedColumns
from reportlab.platypus.frames import Frame

# Base file directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Factor to convert cm to inches
CM_CONVERSION_FACTOR = 2.54

# Register fonts
pdfmetrics.registerFont(
    TTFont(
        "Franklin_Gothic_Book_Italic", BASE_DIR + "/fonts/FranklinGothicBookItalic.ttf"
    )
)
pdfmetrics.registerFont(
    TTFont("Franklin_Gothic_Book", BASE_DIR + "/fonts/FranklinGothicBook.ttf")
)
pdfmetrics.registerFont(
    TTFont(
        "Franklin_Gothic_Demi_Regular",
        BASE_DIR + "/fonts/FranklinGothicDemiRegular.ttf",
    )
)
pdfmetrics.registerFont(
    TTFont(
        "Franklin_Gothic_Medium_Italic",
        BASE_DIR + "/fonts/FranklinGothicMediumItalic.ttf",
    )
)
pdfmetrics.registerFont(
    TTFont(
        "Franklin_Gothic_Medium_Regular",
        BASE_DIR + "/fonts/FranklinGothicMediumRegular.ttf",
    )
)

# Set page parameters
defaultPageSize = letter
PAGE_HEIGHT = defaultPageSize[1]
PAGE_WIDTH = defaultPageSize[0]


def gen_pdf(scan_dict, current_date):
    """Generate PDF with data passed in the data dictionary."""
    # Load in all scan result data
    data_dict = load_scan_data(scan_dict)

    # Content page template (title/summary templates also available)
    def contentPage(canvas, doc):
        """Build the header and footer content for the rest of the pages in the report."""
        canvas.saveState()
        canvas.setFont("Franklin_Gothic_Book", 12)
        canvas.setStrokeColor("#a7a7a6")
        canvas.setFillColor("#a7a7a6")
        canvas.drawImage(BASE_DIR + "/assets/cisa.png", 45, 705, width=65, height=65)
        canvas.drawString(130, 745, "Posture and Exposure Scan Results")
        canvas.drawString(130, 725, "Scan Date: " + current_date)
        canvas.line(130, 710, PAGE_WIDTH - inch, 710)
        canvas.drawRightString(
            PAGE_WIDTH - inch, 0.75 * inch, "P&E Scan Results | Page %d" % (doc.page)
        )
        canvas.drawString(inch, 0.75 * inch, current_date)
        canvas.setFont("Franklin_Gothic_Medium_Regular", 12)
        canvas.setFillColor("#FFC000")
        canvas.drawString(6.4 * inch, 745, "TLP: AMBER")
        canvas.restoreState()

    # Heading bookmark function for TOC
    def bookmarkHeading(text, sty):
        """Add a bookmark to heading element to allow linking from the table of contents."""
        # create bookmarkname
        bn = sha256((text + sty.name).encode("utf8")).hexdigest()
        # modify paragraph text to include an anchor point with name bn
        h = Paragraph(text + '<a name="%s"/>' % bn, sty)
        # store the bookmark name on the flowable so afterFlowable can see this
        h._bookmarkName = bn
        return h

    # Create font and formatting styles (more avalable)
    PS = ParagraphStyle
    # centered = PS(
    #     name="centered",
    #     fontName="Franklin_Gothic_Medium_Regular",
    #     fontSize=20,
    #     leading=16,
    #     alignment=1,
    #     spaceAfter=10,
    #     spaceBefore=10,
    # )
    h3 = PS(
        name="Heading3",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=14,
        leading=10,
        textColor=HexColor("#003e67"),
        spaceAfter=10,
    )
    body = PS(
        name="body",
        leading=14,
        fontName="Franklin_Gothic_Book",
        fontSize=12,
    )
    kpi = PS(
        name="kpi",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=14,
        leading=16,
        alignment=1,
        spaceAfter=20,
    )
    figure = PS(
        name="figure",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=12,
        leading=16,
        alignment=1,
    )
    table = PS(
        name="table",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=12,
        leading=16,
        alignment=1,
        spaceAfter=12,
    )
    table_header = PS(
        name="table_header",
        fontName="Franklin_Gothic_Medium_Regular",
        fontSize=12,
        leading=16,
        alignment=1,
        spaceAfter=12,
        textColor=HexColor("#FFFFFF"),
    )

    # Create repeatedly used elements
    point12_spacer = ConditionalSpacer(1, 12)
    # horizontal_line = HRFlowable(
    #     width="100%",
    #     thickness=1.5,
    #     lineCap="round",
    #     color=HexColor("#003e67"),
    #     spaceBefore=0,
    #     spaceAfter=1,
    #     hAlign="LEFT",
    #     vAlign="TOP",
    #     dash=None,
    # )

    # --- Begin Building PDF ---
    # Specify PDF file name
    doc = MyDocTemplate(
        f"./output_data/threathunt_scans_{current_date}/scan_results_{current_date}.pdf"
    )
    # Build frames for page structures
    # title_frame = Frame(45, 390, 530, 250, id=None, showBoundary=0)
    frameT = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        PAGE_WIDTH - (2 * inch),
        PAGE_HEIGHT - (2.4 * inch),
        id="normal",
        showBoundary=0,
    )
    doc.addPageTemplates(
        [
            PageTemplate(id="ContentPage", frames=frameT, onPage=contentPage),
            # Add additional page templates here
        ]
    )
    Story = []
    table_ct = 1
    figure_ct = 1

    # Create PDF sections for each of the scans
    if "top_cves" in data_dict.keys():
        # Top CVEs scan section
        Story.append(
            KeepTogether(
                [
                    Paragraph("Cybersixgill Top CVEs Scan", h3),
                    Paragraph(
                        f"""
                        Rated by Cybersixgill's (CSG) Dynamic Vulnerability Exploit (DVE) Score, this state-of-the-art machine
                        learning model automatically predicts the probability of a CVE being exploited.
                        <font face="Franklin_Gothic_Medium_Regular">Table {table_ct}</font> identifies the top 10 CVEs with the highest DVE scores at the time of this scan.
                        """,
                        body,
                    ),
                    point12_spacer,
                    bookmarkHeading(
                        f"Table {table_ct}. Top CVEs.",
                        table,
                    ),
                ]
            )
        )
        Story.append(
            format_table(
                data_dict["top_cves"],
                table_header,
                [1.5 * inch, 4 * inch, 0.75 * inch, 0.75 * inch],  # col widths
                [None, body, None, None],  # col styles
            )
        )
        table_ct += 1
        # Separate scan sections with a page break
        Story.append(PageBreak())
    if "keywords" in data_dict.keys():
        # Keywords scan section
        Story.append(Paragraph("Cybersixgill Keywords Scan", h3))

        Story.append(
            Paragraph(
                """
                Utilizing a custom built search query containing a set of specific keywords and filters, this scan
                pulls all of the relevant results from Cybersixgill for the past 24 hours. Due to the large number
                of records returned by this scan, the following section provides various summary statistics about the
                retrieved data. The full data set can be found in the raw data file sent alongside this report.
                """,
                body,
            ),
        )

        # First KPI row
        keyword_df = data_dict["keywords"]
        total_keyword_results = len(keyword_df)
        num_keyword_sites = keyword_df["site"].nunique()
        row = [
            build_kpi(
                Paragraph(
                    str(total_keyword_results)
                    + """<br/> <font face="Franklin_Gothic_Book" size='10'>Total Number of Results</font>""",
                    style=kpi,
                ),
                2,
            ),
            build_kpi(
                Paragraph(
                    str(num_keyword_sites)
                    + """<br/> <font face="Franklin_Gothic_Book" size='10'>Number of Unique Sites</font>""",
                    style=kpi,
                ),
                2,
            ),
        ]
        Story.append(
            BalancedColumns(
                row,  # the flowables we are balancing
                nCols=2,  # the number of columns
                needed=55,  # the minimum space needed by the flowable
                spaceBefore=0,
                spaceAfter=12,
                showBoundary=False,  # optional boundary showing
                leftPadding=65,  # these override the created frame
                rightPadding=0,  # paddings if specified else the
                topPadding=None,  # default frame paddings
                bottomPadding=None,  # are used
                innerPadding=35,  # the gap between frames if specified else
                # use max(leftPadding,rightPadding)
                name="keyword_total_kpi",  # for identification purposes when stuff goes awry
                endSlack=0.1,  # height disparity allowance ie 10% of available height
            )
        )

        Story.append(
            Paragraph(
                """
                The search query filters narrow down the results to only include findings from dark web forums,
                dark web marketplaces, dark web ransomware, CERTs, and ISACs.
                """,
                body,
            ),
        )

        # Second KPI row
        keyword_forum_posts = len(keyword_df.loc[keyword_df["source_type"] == "forum"])
        keyword_market_posts = len(
            keyword_df.loc[keyword_df["source_type"] == "market"]
        )
        keyword_ransom_posts = len(keyword_df.loc[keyword_df["source_type"] == "rw"])
        row = [
            build_kpi(
                Paragraph(
                    str(keyword_forum_posts)  # value displayed
                    + """<br/> <font face="Franklin_Gothic_Book" size='10'>Dark Web Forum Posts</font>""",
                    style=kpi,
                ),
                2,
            ),
            build_kpi(
                Paragraph(
                    str(keyword_market_posts)  # value displayed
                    + """<br/> <font face="Franklin_Gothic_Book" size='10'>Dark Web Market Posts</font>""",
                    style=kpi,
                ),
                2,
            ),
            build_kpi(
                Paragraph(
                    str(keyword_ransom_posts)  # value displayed
                    + """<br/> <font face="Franklin_Gothic_Book" size='10'>Dark Web Ransomware Posts</font>""",
                    style=kpi,
                ),
                2,
            ),
        ]
        Story.append(
            BalancedColumns(
                row,  # the flowables we are balancing
                nCols=3,  # the number of columns
                needed=55,  # the minimum space needed by the flowable
                spaceBefore=0,
                spaceAfter=12,
                showBoundary=False,  # optional boundary showing
                leftPadding=4,  # these override the created frame
                rightPadding=0,  # paddings if specified else the
                topPadding=None,  # default frame paddings
                bottomPadding=None,  # are used
                innerPadding=8,  # the gap between frames if specified else
                # use max(leftPadding,rightPadding)
                name="keywords_breakdown_kpis",  # for identification purposes when stuff goes awry
                endSlack=0.1,  # height disparity allowance ie 10% of available height
            )
        )

        # Unique sites table
        site_table = keyword_df[["site", "site_grade"]]
        site_table.drop_duplicates(inplace=True)
        site_table.rename(
            columns={"site": "Site", "site_grade": "Site Grade"}, inplace=True
        )
        site_table.sort_values(
            by=["Site Grade"],
            ascending=False,
            inplace=True,
        )
        Story.append(
            Paragraph(
                f"""
                <font face="Franklin_Gothic_Medium_Regular">Table {table_ct}</font> lists all of the unique sites these scan results were collected from.
                Additionally, each site's associated Cybersixgill rating has also been included, the higher the rating the more notorious/malicious the
                site is. The prefix "rw" is an abbreviation for ransomware.
                """,
                body,
            )
        )
        Story.append(point12_spacer)
        Story.append(
            bookmarkHeading(
                f"""
                Table {table_ct}. Unique Sites.
                """,
                table,
            )
        )
        Story.append(
            format_table(
                site_table,
                table_header,
                [5.5 * inch, 1 * inch],
                [body, None],
            )
        )
        table_ct += 1

        # Historical data line graph
        Story.append(PageBreak())
        Story.append(
            Paragraph(
                f"""
                <font face="Franklin_Gothic_Medium_Regular">Figure {figure_ct}</font> shows the total number of keyword
                query results for the past 4 days.
                """,
                body,
            )
        )
        Story.append(point12_spacer)
        Story.append(
            KeepTogether(
                [
                    bookmarkHeading(
                        """
                            Figure 1. Historic Query Result Counts.
                        """,
                        figure,
                    ),
                    get_image(
                        f"./output_data/threathunt_scans_{current_date}/figures/keyword_line_chart.png",
                        width=6.5 * inch,
                    ),
                ]
            )
        )
        figure_ct += 1

        # Separate scan sections with a page break
        Story.append(PageBreak())
    if "test_scan" in data_dict.keys():
        # Test scan section
        Story.append(
            KeepTogether(
                [
                    Paragraph("Test Placeholder Scan", h3),
                    Paragraph(
                        f"""
                        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
                        Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure
                        dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat
                        non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
                        <font face="Franklin_Gothic_Medium_Regular">Table {table_ct}</font> identifies the results of this scan.
                        """,
                        body,
                    ),
                    point12_spacer,
                    bookmarkHeading(
                        f"Table {table_ct}. Scan Results.",
                        table,
                    ),
                ]
            )
        )
        Story.append(
            format_table(
                data_dict["test_scan"],
                table_header,
                [1.5 * inch, 4 * inch, 0.75 * inch, 0.75 * inch],  # col widths
                [None, body, None, None],  # col styles
            )
        )
        # Separate scan sections with a page break
        Story.append(PageBreak())
        table_ct += 1

    # Once all scan sections added, build the PDF
    doc.multiBuild(Story)


# --- Helper Functions ---
def load_scan_data(scan_dict):
    """Load in all scan result data from csv files."""
    data_dict = {}
    if "Top CVEs" in scan_dict:
        # Load Top CVEs data if available
        top_cves_df = pd.read_csv(scan_dict.get("Top CVEs"), index_col=0)
        # Formatting for PDF
        top_cves_df = top_cves_df.rename(
            columns={
                "cve_id": "CVE",
                "summary": "Description",
                "cybersixgill_dve_score": "DVE",
                "nvd_v3_score": "CVSSv3",
            }
        )
        top_cves_df["published"] = top_cves_df["published"].str[:10]
        top_cves_df["last_mentioned"] = top_cves_df["last_mentioned"].str[:10]
        top_cves_df["attr_has_been_exploited_in_wild"] = top_cves_df[
            "attr_has_been_exploited_in_wild"
        ].astype(str)
        top_cves_df["attr_is_trending_underground"] = top_cves_df[
            "attr_is_trending_underground"
        ].astype(str)
        top_cves_df["attr_is_verified"] = top_cves_df["attr_is_verified"].astype(str)
        top_cves_df["Description"] = (
            "<font face='Franklin_Gothic_Medium_Regular'>Summary: </font>"
            + top_cves_df["Description"]
            + "<br/><font face='Franklin_Gothic_Medium_Regular'>First Published: </font>"
            + top_cves_df["published"]
            + "<br/><font face='Franklin_Gothic_Medium_Regular'>Has Been Exploited in the Wild: </font>"
            + top_cves_df["attr_has_been_exploited_in_wild"]
            + "<br/><font face='Franklin_Gothic_Medium_Regular'>Verified by Exploit-DB: </font>"
            + top_cves_df["attr_is_verified"]
            + "<br/><font face='Franklin_Gothic_Medium_Regular'>Considered \"Trending Underground\" by CSG: </font>"
            + top_cves_df["attr_is_trending_underground"]
            + "<br/><font face='Franklin_Gothic_Medium_Regular'>Last Mention Detected by CSG: </font>"
            + top_cves_df["last_mentioned"]
            + "<br/><font face='Franklin_Gothic_Medium_Regular'>NVD Link: </font><br/>"
            + top_cves_df["nvd_link"]
        )
        top_cves_df = top_cves_df[["CVE", "Description", "DVE", "CVSSv3"]]
        data_dict.update(top_cves=top_cves_df)
    if "Keywords" in scan_dict:
        # Load Top CVEs data if available
        keywords_df = pd.read_csv(scan_dict.get("Keywords"), index_col=0)
        data_dict.update(keywords=keywords_df)
    if "test_scan" in scan_dict:
        # Load test scan data if avaiable
        test_scan_df = pd.read_csv(scan_dict.get("test_scan"), index_col=0)
        # Formatting for PDF
        test_scan_df = test_scan_df.rename(
            columns={
                "cve_id": "CVE",
                "summary": "Description",
                "cybersixgill_dve_score": "DVE",
                "nvd_v3_score": "CVSSv3",
            }
        )
        test_scan_df = test_scan_df[["CVE", "Description", "DVE", "CVSSv3"]]
        data_dict.update(test_scan=test_scan_df)

    # Return all scan data needed for PDF
    return data_dict


def build_kpi(data, width):
    """Build a KPI element."""
    table = Table(
        [[data]],
        colWidths=[width * inch],
        rowHeights=60,
        style=None,
        splitByRow=1,
        repeatRows=0,
        repeatCols=0,
        rowSplitRange=None,
        spaceBefore=None,
        spaceAfter=None,
        cornerRadii=[10, 10, 10, 10],
    )

    style = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 1), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (0, 0), 1, HexColor("#003e67")),
            ("BACKGROUND", (0, 0), (0, 0), HexColor("#DEEBF7")),
        ]
    )
    table.setStyle(style)
    return table


def format_table(
    df, header_style, column_widths, column_style_list, remove_symbols=False
):
    """Read in a dataframe and convert it to a table and format it with a provided style list."""
    header_row = [
        [Paragraph(str(cell), header_style) for cell in row] for row in [df.columns]
    ]
    data = []
    for row in np.array(df).tolist():
        current_cell = 0
        current_row = []
        for cell in row:
            if column_style_list[current_cell] is not None:
                # Remove emojis from content because the report generator can't display them
                cell = Paragraph(
                    demoji.replace(str(cell), "").replace("&", "[and]"),
                    column_style_list[current_cell],
                )

            current_row.append(cell)
            current_cell += 1
        data.append(current_row)
    data = header_row + data
    table = Table(
        data,
        colWidths=column_widths,
        rowHeights=None,
        style=None,
        splitByRow=1,
        repeatRows=1,
        repeatCols=0,
        rowSplitRange=(2, -1),
        spaceBefore=None,
        spaceAfter=None,
        cornerRadii=None,
    )
    style = TableStyle(
        [
            ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 1), (-1, -1), "MIDDLE"),
            ("INNERGRID", (0, 0), (-1, -1), 1, "white"),
            ("TEXTFONT", (0, 1), (-1, -1), "Franklin_Gothic_Book"),
            ("FONTSIZE", (0, 1), (-1, -1), 12),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [HexColor("#FFFFFF"), HexColor("#DEEBF7")],
            ),
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1d5288")),
            ("LINEBELOW", (0, -1), (-1, -1), 1.5, HexColor("#1d5288")),
        ]
    )
    table.setStyle(style)
    if len(df) == 0:
        label = Paragraph(
            "No Data to Report",
            ParagraphStyle(
                name="centered",
                fontName="Franklin_Gothic_Medium_Regular",
                textColor=HexColor("#a7a7a6"),
                fontSize=16,
                leading=16,
                alignment=1,
                spaceAfter=10,
                spaceBefore=10,
            ),
        )
        table = KeepTogether([table, label])
    return table


def gen_line_chart(save_file, df, x_label, y_label, width, height):
    """Build line chart."""
    value_column = df[df.columns[0]]  # x-values
    # Setup chart to be filled
    color = ["#7aa5c1", "#e08493"]
    fig, ax = plt.subplots()
    ax.spines["right"].set_visible(False)
    ax.spines["top"].set_visible(False)
    plt.set_loglevel("WARNING")
    plt.plot(
        df.index,
        value_column,
        color=color[0],
        label=df.columns[0],
        linewidth=3,
        marker=".",
        markersize=10,
    )
    # If there are two lines to plot, make one dashed
    if len(df.columns) == 2:
        plt.plot(
            df.index,
            df[df.columns[1]],
            color=color[1],
            label=df.columns[1],
            linewidth=3,
            linestyle="dashed",
            marker=".",
            markersize=10,
        )
    y_max = df.to_numpy().max() * 1.1  # updated code
    plt.ylim(ymin=0, ymax=y_max * 1.10)
    # plt.legend(loc=9, ncol=2, framealpha=0, fontsize=8, bbox_to_anchor=(0.5, -0.5))
    plt.legend(loc="upper right")
    plt.gcf().set_size_inches(
        width / CM_CONVERSION_FACTOR, height / CM_CONVERSION_FACTOR
    )
    plt.xticks(fontsize=7)
    plt.yticks(fontsize=7)
    plt.gca().set_ylabel(y_label, labelpad=10, fontdict={"size": 8})
    plt.xlabel(x_label, labelpad=10, fontdict={"size": 8})
    plt.xticks(rotation=0)
    plt.grid(axis="y")
    # Add legend
    plt.legend(loc="upper right")
    # Set sizing for image
    plt.gcf().set_size_inches(
        width / CM_CONVERSION_FACTOR, height / CM_CONVERSION_FACTOR
    )
    plt.tight_layout()

    # iterate over dataframe rows and begin to plot points
    for row in df.itertuples():
        if len(row) == 2:
            # If there is only 1 line to plot (1 set of y-values)
            plt.annotate(
                str(int(row[1])),
                xy=(row[0], row[1]),
                textcoords="offset points",  # how to position the text
                xytext=(
                    0,
                    8,
                ),  # distance from text to points (x,y)
                ha="center",  # horizontal alignment can be left, right or center
                # fontsize=2,
                color="#003e67",
            )
        elif len(row) == 3:
            # If there are 2 lines to plot (2 sets of y-values)
            # check if the two values are within 1/10th of the max y value
            value_diff = abs(row[1] - row[2])
            if value_diff < y_max / 10:
                # If data points are close together, prevent labels from overlapping
                if min(row[1], row[2]) < y_max / 4:
                    # if the values are on the bottom quarter of the graph don't label below values
                    y1 = y2 = max(row[1], row[2])
                    if row[1] > row[2]:
                        y1_offset = 18
                        y2_offset = 8
                    else:
                        y1_offset = 8
                        y2_offset = 18
                else:
                    # If values are above bottom quarter, label below values
                    y1 = row[1]
                    y2 = row[2]
                    if row[1] > row[2]:
                        y1_offset = 8
                        y2_offset = -17
                    else:
                        y1_offset = -17
                        y2_offset = 8
            else:
                # if values are not close, put the labels directly above each
                y1 = row[1]
                y2 = row[2]
                y1_offset = 8
                y2_offset = 8

            plt.annotate(
                str(int(row[1])),
                xy=(row[0], y1),
                textcoords="offset points",  # how to position the text
                xytext=(
                    0,
                    y1_offset,
                ),  # distance from text to points (x,y)
                ha="center",  # horizontal alignment can be left, right or center
                # fontsize=2,
                color="#005288",
            )
            plt.annotate(
                str(int(row[2])),
                xy=(row[0], y2),
                textcoords="offset points",  # how to position the text
                xytext=(
                    0,
                    y2_offset,
                ),  # distance from text to points (x,y)
                ha="center",  # horizontal alignment can be left, right or center
                # fontsize=2,
                color="#c41230",
            )

    # Once line chart is generated, save it to png
    plt.savefig(
        save_file + "/figures/keyword_line_chart.png",
        transparent=True,
        dpi=500,
        bbox_inches="tight",
    )
    plt.clf()


def get_image(path, width=1 * inch):
    """Read in an image and scale it based on the width argument."""
    img = utils.ImageReader(path)
    iw, ih = img.getSize()
    aspect = ih / float(iw)
    return Image(path, width=width, height=(width * aspect))


class MyDocTemplate(BaseDocTemplate):
    """Extend the BaseDocTemplate to adjust Template."""

    # Has to do with building the actual PDF?

    def __init__(self, filename, **kw):
        """Initialize MyDocTemplate."""
        self.allowSplitting = 0
        BaseDocTemplate.__init__(self, filename, **kw)
        self.pagesize = defaultPageSize


class ConditionalSpacer(Spacer):
    """Extend spacer to conditionaly shrink if near the end of the page."""

    def wrap(self, availWidth, availHeight):
        """Change hight of spacer based on available height."""
        height = min(self.height, availHeight - 1e-8)
        return (availWidth, height)
