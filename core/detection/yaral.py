import argparse

def generate_yara_l_rule(rule_name, general_description, events, associations, match='all over 5m', condition='all of them'):
    yara_l_rule = f'rule {rule_name}\n{{\n'

    yara_l_rule += '    meta:\n'
    yara_l_rule += f'        description = "{general_description}"\n'

    yara_l_rule += '    events:\n'
    for key, value in events.items():
        yara_l_rule += f'        {key} = "{value}"\n'

    yara_l_rule += '    associations:\n'
    for association in associations:
        yara_l_rule += f'        {association}\n'

    yara_l_rule += f'    match:\n        {match}\n'
    yara_l_rule += f'    condition:\n        {condition}\n}}'

    return yara_l_rule


def define_events(api_events, variable_prefix_associations, section_associations):
    events = {}
    for i, api in enumerate(api_events):
        event_parts = api.split(":")
        event_name_key = f'${variable_prefix_associations}.{section_associations}.eventName_{i + 1}'
        event_source_key = f'${variable_prefix_associations}.{section_associations}.eventSource_{i + 1}'
        events[event_name_key] = event_parts[1]
        events[event_source_key] = event_parts[0]
    return events


def define_associations(variable_prefix_associations, section_associations, type_associations):
    associations = []
    associations.append(f'${variable_prefix_associations}.{section_associations}.{type_associations} = ${type_associations}')
    return associations


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate YARA-L rule")
    parser.add_argument("-r", "-RuleName", required=True, help="Rule name")
    parser.add_argument("-d", "-GeneralDescription", required=True, help="Description of the YARA-L rule")
    parser.add_argument("-e", "-Events", required=True, help="Events for the YARA-L rule")
    parser.add_argument("-a", "-Associations", nargs='+', required=True, help="Associations for the YARA-L rule")
    parser.add_argument("-m", "-Match", required=True, help="Match logic for the YARA-L rule")
    parser.add_argument("-c", "-Condition", nargs='+', help="Condition logic for the YARA-L rule")
    args = parser.parse_args()

    yara_l_rule = generate_yara_l_rule(args.RuleName, args.GeneralDescription, args.Events, args.Associations, args.Match, args.Condition)
    print(yara_l_rule)