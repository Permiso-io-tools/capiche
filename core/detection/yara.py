import argparse

def generate_yara_rule(rule_name, meta_author, meta_description, strings, condition, meta_dynamic_dictionary=None):
    yara_rule = f'rule {rule_name}\n{{\n'

    yara_rule += '    meta:\n'
    yara_rule += f'        author = "{meta_author}"\n'
    yara_rule += f'        description = "{meta_description}"\n'

    if meta_dynamic_dictionary:
        for item in meta_dynamic_dictionary:
            for key, value in item.items():
                yara_rule += f'        {key} = "{value}"\n'

    yara_rule += '    strings:\n'
    for yara_string in strings:
        yara_rule += f'        {yara_string}\n'

    yara_rule += f'    condition:\n        {condition}\n}}'

    return yara_rule


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate YARA rule")
    parser.add_argument("-r", "-RuleName", required=True, help="Rule name")
    parser.add_argument("-a", "-MetaAuthor", required=True, help="Author for the YARA rule")
    parser.add_argument("-d", "-MetaDescription", required=True, help="Description for the YARA rule")
    parser.add_argument("-s", "-Strings", nargs='+', required=True, help="List of YARA strings")
    parser.add_argument("-c", "-Condition", required=True, help="Condition for the YARA rule")
    parser.add_argument("-dd", "-MetaDynamicDictionary", nargs='+', help="Dynamic metadata for the YARA rule")
    args = parser.parse_args()

    yara_rule = generate_yara_rule(args.RuleName, args.MetaAuthor, args.MetaDescription, args.Strings, args.Condition, args.MetaDynamicDictionary)
    print(yara_rule)