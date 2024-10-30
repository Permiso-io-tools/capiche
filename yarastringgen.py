import argparse
import re
from transform import load_api_data,transform_api_list

def generate_yara_string(api_data, strings, variable_prefix, modifiers, comment, comment_api_description):
    yara_strings = []

    for i, api in enumerate(strings, start=1):
        for info in api_data:
            original_api_name = info['EventSource'] + ':' + info['EventName']
            transformed_api_name = info['EventSource'] + ':' + re.sub(r'(?<=[a-z])([A-Z])', r'_\1', info['EventName']).lower().lstrip('_')
            if transformed_api_name == api or original_api_name == api or transformed_api_name.replace('_', '-') == api:
                description = info['Description']
                break
        else:
            description = "No description available"

        api_name = api.split(":")[-1]

        variable_name = f'{variable_prefix}_{i:02}'
        yara_comment = f"{comment} - API Description: {description}" if comment_api_description else comment
        yara_string = f"${variable_name} = \"{api_name}\" {modifiers} // {yara_comment}"
        yara_strings.append(yara_string)

    return yara_strings

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
        if match:
            api_name = match.group(1)
            content_strings.append(f'content:"{api_name}"')
        else:
            content_strings.append(f'content:"{string}"')


    vt_syntax = f" {logical_operator} ".join(content_strings)

    if not content_strings:
        return ""

    return f"({vt_syntax})"


def generate_google_dork_syntax(strings, logical_operator="", operator=""):
    if logical_operator not in {"OR", "AND"}:
        raise ValueError("Logical operator must be 'OR' or 'AND'.")

    if isinstance(strings, str):
        return f'{operator}:"{strings}"'

    dork_syntax = ""

    for string in strings:
        match = re.search(r'"([^"]+)"', string)
        if match:
            content = match.group(1)
            dork_syntax += f'{operator}:"{content}" {logical_operator} '
        else:
            dork_syntax += f'{operator}:"{string}" {logical_operator} '

    dork_syntax = dork_syntax[:-len(logical_operator) - 1]

    return f"({dork_syntax.strip()})"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate YARA strings")
    parser.add_argument("-SDK", required=True, help="SDK type (boto or awscli)")
    parser.add_argument("-APIList", nargs='+', required=True, help="List of APIs")
    parser.add_argument("-VariablePrefix", required=True, help="Variable prefix")
    parser.add_argument("-Modifiers", required=True, help="YARA string modifiers")
    parser.add_argument("-Comment", required=True, help="Comment for the YARA strings")
    parser.add_argument("-CommentApiDescription", action="store_true", help="Include API description in comments")
    args = parser.parse_args()

    api_data = load_api_data('api_list_aws.json')

    api_result = transform_api_list(args.SDK, args.APIList)
    yara_strings = generate_yara_string(api_data, api_result['APIListTransformed'], args.VariablePrefix, args.Modifiers, args.Comment, args.CommentApiDescription)

    for yara_string in yara_strings:
        print(yara_string)

    vt_syntax = generate_vtgrep_content(yara_strings)
    print(vt_syntax)


