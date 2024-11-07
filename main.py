# Import all functions
from core.helper.transform import load_api_data, transform_api_list
from core.helper.search import search_api_name, search_api_description
from core.helper.yarastringgen import generate_yara_string
from core.detection.yara import generate_yara_rule
from core.detection.sigma import generate_sigma_rule
from core.detection.vtgrep import generate_vtgrep_content
from core.detection.googledork import generate_google_dork_syntax
from core.detection.yaral import generate_yara_l_rule, define_events, define_associations
from core.arguments.arguments import parseargs

# Import JSON list of all AWS API names and descriptions
api_data = load_api_data('./core/api_list_aws.json')

args = parseargs()

if __name__ == '__main__':

    if args.usage == "GOOGLEDORK":
        google_dork_rule = generate_google_dork_syntax(args.s, args.lo, args.o)
        print(google_dork_rule)

    elif args.usage == "SIGMA":
        sigma_rule = generate_sigma_rule(args.r, args.d, api_data, args.api, args.s, args.ua)
        print(sigma_rule)

    elif args.usage == "VTGREP":
        vtgrep_rule = generate_vtgrep_content(args.s, args.lo)
        print(vtgrep_rule)

    elif args.usage == "YARA":
        yara_rule = generate_yara_rule(args.r, args.a, args.d, args.s, args.c, args.dd)
        print(yara_rule)

    elif args.usage == "YARAL":
        yara_l_rule = generate_yara_l_rule(args.r, args.d, args.e, args.a, args.m, args.c)
        print(yara_l_rule)