import argparse
import re

def generate_vtgrep_content(strings, logical_operator=""):
    if isinstance(strings, str):
        return f'content:"{strings}"'

    if not isinstance(strings, list):
        raise ValueError("Input must be a list of strings or a single string.")

    if logical_operator not in {"OR", "AND"}:
        raise ValueError("Logical operator must be 'OR' or 'AND'.")

    content_strings = []

    for string in strings:

        match = re.search(r'"([^"]+)"', string)
        api_name = match.group(1) if match else string
        api_name = api_name.split(":")[-1]

        content_strings.append(f'content:"{api_name}"')

    vt_syntax = f" {logical_operator} ".join(content_strings)

    if not content_strings:
        return ""

    return f"({vt_syntax})"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate VTGrep rule")
    parser.add_argument("-s", "-Strings", nargs='+', required=True, help="Strings for VTGrep rule")
    parser.add_argument("-lo", "-LogicalOperator", required=True, help="Logical operator to apply between each input string for VTGrep rule")
    args = parser.parse_args()

    vtgrep_rule = generate_vtgrep_content(args.Strings, args.LogicalOperator)
    print(vtgrep_rule)