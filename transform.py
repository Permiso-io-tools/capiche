import json
import argparse
import re

def load_api_data(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def transform_api_list(api_data, sdk: str, matched_apis):
    if isinstance(matched_apis, str):
        matched_apis = [matched_apis]

    if not isinstance(matched_apis, list):
        raise ValueError("Invalid format for matched APIs. Expected string or list.")

    transformed_api_list = []

    for api_info in api_data:
        api_key = api_info['EventSource'] + ':' + api_info['EventName']
        if api_key in matched_apis:
            service = api_info['EventSource']
            api_name = api_info['EventName']

            transformed_api_name = re.sub(r'(?<=[a-z])([A-Z])', r'_\1', api_name).lower().lstrip('_')

            if sdk.lower() == 'boto':
                transformed_api = transformed_api_name
            elif sdk.lower() == 'awscli':
                transformed_api = transformed_api_name.replace('_', '-')
            else:
                raise ValueError("Invalid SDK type. Supported values are 'boto' or 'awscli'.")

            transformed_api_list.append(f"{service}:{transformed_api}")

    result = {
#       "SDK": sdk,
#        "APIList": matched_apis,
        "APIListTransformed": transformed_api_list,
#        "APIData": api_data
    }

    return result



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Transform API list")
    parser.add_argument("-SDK", required=True, choices=['boto', 'awscli'], help="SDK type (boto or awscli)")
    parser.add_argument("-MatchedAPIs", nargs='+', required=True, help="List of matched APIs in the format 'EventSource:EventName' or directly provided API names")
    args = parser.parse_args()

    api_data = load_api_data('api_list_aws.json')

    api_result = transform_api_list(api_data, args.SDK, args.MatchedAPIs)
    print(json.dumps(api_result))
