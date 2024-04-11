#!/usr/bin/env python3

import json
import sys

## Example input data
# [
#     {
#         "profileName": "redhat-enterprise-linux-8-stig-baseline",
#         "resultSets": ["rhel-8_hardened.json"],
#         "compliance": 66,
#         "passed": {"critical": 0, "high": 11, "medium": 208, "low": 8, "total": 227},
#         "failed": {"critical": 0, "high": 6, "medium": 87, "low": 19, "total": 112},
#         "skipped": {"critical": 0, "high": 1, "medium": 1, "low": 1, "total": 3},
#         "error": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
#         "no_impact": {"none": 33, "total": 33},
#     }
# ]

## Desired output Table

# # redhat-enterprise-linux-8-stig-baseline
# ## Result Sets: rhel-8_hardened.json

# |                  | Compliance (%) | Passed | Failed | Not Reviewed | Not Applicable | Error |
# | ---------------- | -------------- | ------ | ------ | ------------ | -------------- | ----- |
# | **Total**        | 66             | 227    | 112    | 3            | 33             | 0     |
# | **Critical**     | -              | 0      | 0      | 0            | -              | 0     |
# | **High**         | -              | 11     | 6      | 1            | -              | 0     |
# | **Medium**       | -              | 208    | 87     | 1            | -              | 0     |
# | **Low**          | -              | 8      | 19     | 1            | -              | 0     |
# | **Not Applicable** | -            | -      | -      | -            | 33             | -     |

import json
import sys

# Load your JSON data from standard input
data = json.load(sys.stdin)

# Extract the first item from the list (assuming there's only one item)
data = data[0]

# Define the order of the rows and columns
row_order = ["Total", "Critical", "High", "Medium", "Low", "Not Applicable"]
column_order = [
    "Passed :white_check_mark:",
    "Failed :x:",
    "Not Reviewed :leftwards_arrow_with_hook:",
    "Not Applicable :heavy_minus_sign:",
    "Error :warning:",
]

# Calculate the maximum width of each column
column_widths = [max(len(row), len(col)) for row, col in zip(row_order, column_order)]
column_widths = [max(column_widths)] * len(
    column_widths
)  # Make all columns the same width for a cleaner look

# Generate the Markdown table
table = (
    "| "
    + "Compliance: "
    + str(data["compliance"])
    + "% :test_tube:"
    + " | "
    + " | ".join(col.ljust(width) for col, width in zip(column_order, column_widths))
    + " |\n"
)

table += (
    "| "
    + "-".ljust(max(column_widths), "-")
    + " | "
    + " | ".join("-".ljust(width, "-") for width in column_widths)
    + " |\n"
)
for row in row_order:
    if row == "Total":
        values = [
            str(data["passed"]["total"]),
            str(data["failed"]["total"]),
            str(data["skipped"]["total"]),
            str(data["no_impact"]["total"]),
            str(data["error"]["total"]),
        ]
    elif row == "Not Applicable":
        values = ["-", "-", "-", str(data["no_impact"]["total"]), "-"]
    else:
        values = [
            str(data["passed"][row.lower()]),
            str(data["failed"][row.lower()]),
            str(data["skipped"][row.lower()]),
            "-",
            str(data["error"][row.lower()]),
        ]
    table += (
        "| "
        + ("**" + row + "**").ljust(max(column_widths) + 2)
        + " | "
        + " | ".join(val.ljust(width) for val, width in zip(values, column_widths))
        + " |\n"
    )

print(table)
