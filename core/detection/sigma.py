import argparse
from datetime import datetime
from core.helper.transform import load_api_data,transform_api_list

def generate_sigma_rule(rule_name, description, api_data, api_list, sdk, useragent):
    transformed_api_list = transform_api_list(api_data, sdk, api_list)

    event_names = [api.split(':')[1] for api in transformed_api_list]
    event_sources = set(api.split(':')[0] + ".amazonaws.com" for api in transformed_api_list)

    if not event_names:
        raise ValueError("No matching event names found in the provided API data.")

    logsource_product = "aws"
    logsource_service = "cloudtrail"

    sigma_rule = {
        "title": rule_name,
        "id": None,
        "status": None,
        "description": description,
        "references": None,
        "author": "CAPICHE",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "tags": None,
        "logsource": {
            "product": logsource_product,
            "service": logsource_service
        },
        "detection": {
            "selection": {
                "eventSource": list(event_sources),
                "eventName": event_names,
                "userAgent|contains": useragent
            },
            "condition": "selection"
        },
        "falsepositives": [
            "Valid usage"
        ],
        "level": "medium"
    }

    newline = "\n"
    yaml_output = f"""
title: {sigma_rule['title']}
description: {sigma_rule['description']}
author: {sigma_rule['author']}
date: {sigma_rule['date']}
logsource:
  product: {sigma_rule['logsource']['product']}
  service: {sigma_rule['logsource']['service']}
detection:
  selection:
    eventSource: 
      - {f"{newline}      - ".join([f"'{source}'" for source in sigma_rule['detection']['selection']['eventSource']])}
    eventName: 
      - {f"{newline}      - ".join([f"'{name}'" for name in sigma_rule['detection']['selection']['eventName']])}
    userAgent|contains: '{sigma_rule['detection']['selection']['userAgent|contains']}'
  condition: {sigma_rule['detection']['condition']}
falsepositives:
  - {sigma_rule['falsepositives'][0]}
level: {sigma_rule['level']}
"""

    if sigma_rule['id']:
        yaml_output += f"id: {sigma_rule['id']}\n"

    if sigma_rule['status']:
        yaml_output += f"status: {sigma_rule['status']}\n"

    if sigma_rule['references']:
        yaml_output += f"references: {sigma_rule['references']}\n"

    if sigma_rule['tags']:
        yaml_output += f"tags: {sigma_rule['tags']}\n"

    return yaml_output.strip()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Sigma rule")
    parser.add_argument("-r", "-RuleName", required=True, help="Rule name")
    parser.add_argument("-d", "-Description", required=True, help="Description for the Sigma rule")
    parser.add_argument("-api", "-APIList", nargs='+', required=True, help="List of APIs in the format 'EventSource:EventName'")
    parser.add_argument("-s", "-SDK", required=True, choices=['boto', 'awscli'], help="SDK type (boto or awscli)")
    parser.add_argument("-ua", "-UserAgent", required=True, help="User agent to match the selected SDK")
    args = parser.parse_args()

    api_data = load_api_data('./core/api_list_aws.json')

    sigma_rule = generate_sigma_rule(args.RuleName, args.Description, api_data, args.APIList, args.SDK, args.UserAgent)
    print(sigma_rule)