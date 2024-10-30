def interactive_input(general_description=None, variable_prefix_associations=None, section_associations=None, type_associations=None):
    if general_description is None:
        print("Enter a general description for the YARA rule:")
        general_description = input().strip()

    if variable_prefix_associations is None:
        print("Enter variable prefix, section, and type for associations (e.g., u1 target port):")
        variable_prefix_associations, section_associations, type_associations = input().strip().split()

    return general_description, variable_prefix_associations, section_associations, type_associations


def generate_yara_l_rule(rule_name, general_description, events, associations, match='all over 5m', condition='all of them'):
    yara_rule = f'rule {rule_name}\n{{\n'

    yara_rule += '    meta:\n'
    yara_rule += f'        description = "{general_description}"\n'

    yara_rule += '    events:\n'
    for key, value in events.items():
        yara_rule += f'        {key} = "{value}"\n'

    yara_rule += '    associations:\n'
    for association in associations:
        yara_rule += f'        {association}\n'

    yara_rule += f'    match:\n        {match}\n'
    yara_rule += f'    condition:\n        {condition}\n}}'

    return yara_rule


def define_events(api_user, api_pol, variable_prefix_associations, section_associations):
    events = {}
    for i, api in enumerate(api_user['APIListTransformed'] + api_pol['APIListTransformed']):
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

