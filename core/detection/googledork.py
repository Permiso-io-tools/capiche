import argparse
import re

def generate_google_dork_syntax(strings, logical_operator="", operator=""):
    if logical_operator not in {"OR", "AND", ""}:
        raise ValueError("Logical operator must be 'OR', 'AND' or an empty string.")

    if isinstance(strings, str):
        return f'{operator}:"{strings}"'

    dork_syntax = ""

    for string in strings:

        match = re.search(r'"([^"]+)"', string)
        api_name = match.group(1) if match else string
        api_name = api_name.split(":")[-1]

        dork_syntax += f'{operator}:"{api_name}" '
        if logical_operator:
            dork_syntax += f"{logical_operator} "

    dork_syntax = dork_syntax[:-len(logical_operator) - 1]

    return f"({dork_syntax.strip()})"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Google Dork rule")
    parser.add_argument("-s", "-Strings", nargs='+', required=True, help="Strings for Google Dork rule")
    parser.add_argument("-lo", "-LogicalOperator", required=True, help="Logical operator to apply between each input string for Google Dork rule")
    parser.add_argument("-o", "-Operator", required=True, help="Google Dork operator to be applied (as prefix) to each input string for Google Dork rule")
    args = parser.parse_args()

    google_dork_rule = generate_google_dork_syntax(args.Strings, args.LogicalOperator, args.Operator)
    print(google_dork_rule)