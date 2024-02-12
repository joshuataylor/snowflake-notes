# Reads the snowflake_login_codes.csv file and outputs as a markdown table.
# headers: code,title,description

import csv

csv_file_path = 'snowflake_login_codes.csv'

rows = []
headers = ["code", "title", "description"]

with open(csv_file_path, mode='r', encoding='utf-8') as csv_file:
    csv_reader = csv.DictReader(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    for row in csv_reader:
        rows.append(row)

# stupidly simple markdown table
markdown_table = """# Snowflake Login Codes

Snowflake doesn't seem to have all login codes on one page, they can be found around the docs.

- [Key Pair Authentication Login Error Codes](https://docs.snowflake.com/en/user-guide/key-pair-auth-troubleshooting#list-of-errors)
- [SSO/Federated Auth Login Error Codes](https://docs.snowflake.com/en/user-guide/errors-saml#federated-authentication-error-codes)
- [OAuth Login Error Codes](https://docs.snowflake.com/en/user-guide/oauth-snowflake-overview#error-codes)
- [MFA Login Error Codes](https://docs.snowflake.com/en/user-guide/security-mfa#mfa-error-codes)

> To add a new code, please don't change this file, as it's automatically generated. Instead, change snowflake_login_codes.csv, then run `python snowflake_login-codes.py`

"""

markdown_table += '| ' + ' | '.join(headers) + ' |\n'
markdown_table += '|-' + '-|-'.join([''] * len(headers)) + '-|\n'

# Add each row to the Markdown table
for row in rows:
    markdown_table += '| ' + row['code'] + ' | ' + row['title'] + ' | ' + row['description'] + ' |\n'

# Output the Markdown table to snowflake_login_codes.md
with open('snowflake_login_codes.md', mode='w', encoding='utf-8') as markdown_file:
    markdown_file.write(markdown_table)