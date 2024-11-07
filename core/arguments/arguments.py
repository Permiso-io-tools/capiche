import argparse

def parseargs():
    parser = argparse.ArgumentParser(
                    prog='CAPICHE Detection Framework (Cloud API Conversion Helper Express)',
                    description='A tool designed to simplify each step of the cloud API detection translation pipeline, enabling any defender to instantly create numerous styles of detection rules from groupings of APIs.',
                    epilog='Thank you for using CAPICHE!')
    subparsers = parser.add_subparsers(dest='usage')

    ##GOOGLEDORK
    google_dork_parser = subparsers.add_parser('GOOGLEDORK', help='Generate Google Dork rule')
    google_dork_parser.add_argument("-s", "-Strings", nargs='+', required=True, help="Strings for Google Dork rule")
    google_dork_parser.add_argument("-lo", "-LogicalOperator", required=True, help="Logical operator to apply between each input string for Google Dork rule")
    google_dork_parser.add_argument("-o", "-Operator", required=True, help="Google Dork operator to be applied (as prefix) to each input string for Google Dork rule")
 
    ##SIGMA
    sigma_parser = subparsers.add_parser('SIGMA', help='Generate Sigma rule')
    sigma_parser.add_argument("-r", "-RuleName", required=True, help="Rule name")
    sigma_parser.add_argument("-d", "-Description", required=True, help="Description for the Sigma rule")
    sigma_parser.add_argument("-api", "-APIList", nargs='+', required=True, help="List of APIs in the format 'EventSource:EventName'")
    sigma_parser.add_argument("-s", "-SDK", required=True, choices=['boto', 'awscli'], help="SDK type (boto or awscli)")
    sigma_parser.add_argument("-ua", "-UserAgent", required=True, help="User agent to match the selected SDK")

    ##VTGREP
    vtgrep_parser = subparsers.add_parser('VTGREP', help='Generate VTGrep rule')
    vtgrep_parser.add_argument("-s", "-Strings", nargs='+', required=True, help="Strings for VTGrep rule")
    vtgrep_parser.add_argument("-lo", "-LogicalOperator", required=True, help="Logical operator to apply between each input string for VTGrep rule")

    ##YARA
    yara_parser = subparsers.add_parser('YARA', help='Generate YARA rule')
    yara_parser.add_argument("-r", "-RuleName", required=True, help="Rule name")
    yara_parser.add_argument("-a", "-MetaAuthor", required=True, help="Author for the YARA rule")
    yara_parser.add_argument("-d", "-MetaDescription", required=True, help="Description for the YARA rule")
    yara_parser.add_argument("-s", "-Strings", nargs='+', required=True, help="List of YARA strings")
    yara_parser.add_argument("-c", "-Condition", required=True, help="Condition for the YARA rule")
    yara_parser.add_argument("-dd", "-MetaDynamicDictionary", nargs='+', help="Dynamic metadata for the YARA rule")

    ##YARA-L
    yara_l_parser = subparsers.add_parser('YARAL', help='Generate YARA-L rule')
    yara_l_parser.add_argument("-r", "-RuleName", required=True, help="Rule name")
    yara_l_parser.add_argument("-d", "-GeneralDescription", required=True, help="Description of the YARA-L rule")
    yara_l_parser.add_argument("-e", "-Events", required=True, help="Events for the YARA-L rule")
    yara_l_parser.add_argument("-a", "-Associations", nargs='+', required=True, help="Associations for the YARA-L rule")
    yara_l_parser.add_argument("-m", "-Match", required=True, help="Match logic for the YARA-L rule")
    yara_l_parser.add_argument("-c", "-Condition", nargs='+', help="Condition logic for the YARA-L rule")

    return parser.parse_args()