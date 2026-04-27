"""Functions to redact PII from a dataframe."""

# Standard Python Libraries
import textwrap

# Third-Party Libraries
import pandas as pd


def redact_pii(scrubber, batch_analyzer, batch_anonymizer, df, cols=None):
    """Remove PII from the specified dataframe using Scrubadub and Presidio."""
    print(">>> Beginning redaction of PII")
    # If columns not specified, redact all
    if cols is None:
        cols = list(df.columns.values)

    # Apply Presidio Analyzer/Anonymizer
    print("Applying Presidio Analyzer/Anonymizer")
    print(f"Redacting columns: {cols}")
    df[cols] = df[cols].fillna("")
    # Presidio fields to redact
    redact_entities = [
        "CREDIT_CARD",
        "EMAIL_ADDRESS",
        "IP_ADDRESS",
        "PHONE_NUMBER",
        "US_DRIVER_LICENSE",
        "US_SSN",
        "PERSON",
    ]
    # Iterate over each column that needs to be PII filtered
    for col in cols:
        # Add group numbers column for reassembling chunked rows
        df.insert(0, "group_number", range(1, len(df) + 1))
        # Isolate column for PII filtering
        filter_df = df.loc[:, ["group_number", col]]
        other_df = df.drop(col, axis=1)
        # Break up any large text fields into smaller chunks
        n = 1000  # specify chunk size
        rows_to_chunk = filter_df[col].str.len() > n  # mask
        # w = textwrap.TextWrapper(width=90,break_long_words=False,replace_whitespace=False)
        filter_df.loc[rows_to_chunk, col] = filter_df.loc[rows_to_chunk, col].apply(
            lambda x: textwrap.wrap(text=x, width=n, replace_whitespace=False)
        )
        # Explode rows w/ large text field into multiple rows
        filter_df = filter_df.explode(col)
        # Apply presidio PII filter
        filter_df_dict = filter_df.to_dict(orient="list")
        analyzer_results = list(
            batch_analyzer.analyze_dict(
                filter_df_dict, entities=redact_entities, language="en"
            )
        )
        anonymizer_results = batch_anonymizer.anonymize_dict(
            analyzer_results=analyzer_results
        )
        # Convert back to dataframe and reassemble rows by group
        clean_df = pd.DataFrame(anonymizer_results)
        clean_df = clean_df.groupby(["group_number"], as_index=False).agg(
            {col: lambda x: x.tolist()}
        )
        clean_df[col] = clean_df[col].apply(lambda x: " ".join(x))
        clean_df["group_number"] = pd.to_numeric(
            clean_df["group_number"], errors="coerce"
        )
        clean_df.sort_values(by="group_number", inplace=True)
        # clean_df.to_csv("./post_test_output.csv")
        df = pd.merge(clean_df, other_df, on="group_number", how="inner")
        df.drop("group_number", axis=1, inplace=True)
    print("Finished applying Presidio Analyzer/Anonymizer")

    # Apply Scrubadub Scrubber
    print("Applying Scrubadub Scrubber")
    for col in cols:
        df[col] = df[col].apply(lambda x: scrubber.clean(x))
    print("Finished applying Scrubadub Scrubber")

    # Return redacted dataframe
    print(">>> Finished redacting PII")
    return df
