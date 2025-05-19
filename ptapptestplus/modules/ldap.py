from dataclasses import dataclass
from enum import Enum
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from colorama import Fore, Style, init
from typing import  List, NamedTuple, Optional
import argparse 
import sys

from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out

class VULNS(Enum):
    WeakUsername = "PTV-LDAP-WEAKUSERNAME"
    WeakCredentials = "PTV-LDAP-WEAKCREDENTIALS"
    Write = "PTV-LDAP-WRITEACCESS"

class Credential(NamedTuple):
    username: str | None
    password: str | None

class TestWriteResult(NamedTuple):
    target_dn: str | None
    atribute: str | None
    value: str | None
    credentials: str | None


@dataclass
class LDAPResult:
    Banner: Optional[dict] = None
    Search: Optional[list[dict]] = None
    usernames: Optional[list[str]] = None
    credentials: Optional[list[Credential]] = None
    Writetest: Optional[TestWriteResult] = None

class LDAPArgs(BaseArgs):
    ip: str
    port:int = 389
    command:str
    use_ssl:bool = False
    spray:bool = False
    output_file:str = None
    base_dn:str = None
    upn_domain:str=None
    username_file:str = None
    password_file:str = None
    user:str = None
    password:str = None
    ldap_filter:str ='(ObjectClass=*)'
    attributes: list[str] = None
    search_attribute: str = 'uid'
    cn_uid: list = ['uid', 'cn']
    target_dn:str = None
    attribute:str = 'sn'
    test_value:str = None


    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of SNMP arguments"""

        examples = """example usage:
        ptapptest-plus dns brute-subdomains --domain example.com --subdomains wordlist.txt
        ptapptest-plus dns lookup --domain example.com --lookup-records A MX TXT
        ptapptest-plus dns reverse-dns --ip_file ips.txt
        """

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        ldap_subparsers = parser.add_subparsers(dest="command", help="Select LDAP command", required=True)
    
        # Banner grabbing
        banner_parser = ldap_subparsers.add_parser("banner", help="Retrieve LDAP server banner information")
        banner_parser.add_argument("-ip", required=True, help="Target IP address")
        banner_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        banner_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        banner_parser.add_argument("-u", "--user", help="Username for authenticated bind (format: cn=admin,dc=example,dc=com OR user@example.com)")
        banner_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
        banner_parser.add_argument("-o", "--output", help="Output file to save results")

        # LDAP search
        search_parser = ldap_subparsers.add_parser("search", help="Perform LDAP search query")
        search_parser.add_argument("-ip", required=True, help="Target IP address")
        search_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        search_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        search_parser.add_argument("-u", "--user", help="Username for authenticated bind")
        search_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
        search_parser.add_argument("-bd", "--base-dn", help="Base DN (example: dc=example,dc=com). If not provided, it tries to auto-detect.")
        search_parser.add_argument("-f", "--filter", default="(objectClass=*)", help="""
                                                                                            LDAP search filter (RFC 4515 format).\n
                                                                                            Supports complex expressions with logical operators AND (&), OR (|), and NOT (!).\n\n

                                                                                            Examples:\n
                                                                                            "(objectClass=person)"              - Match all persons\n
                                                                                            "(uid=admin)"                       - Exact UID match\n
                                                                                            "(&(sn=Newton)(cn=Isaac Newton))"  - Match users with surname 'Newton' AND full name 'Isaac Newton'\n
                                                                                            "(|(uid=gauss)(uid=riemann))"      - Match users with UID 'gauss' OR 'riemann'\n
                                                                                            """
                                                                                            )
        search_parser.add_argument("-a", "--attributes", nargs='+', help="List of attributes to retrieve (example: cn mail sn). Default: all")
        search_parser.add_argument("-o", "--output", help="Output file to save results")

        # User Enumeration
        enum_parser = ldap_subparsers.add_parser("userenum", help="Enumerate valid LDAP users")
        enum_parser.add_argument("-ip", required=True, help="Target IP address")
        enum_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        enum_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        enum_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
        enum_parser.add_argument("-bd", "--base-dn", help="Base DN (recommended, but can try to auto-detect)")
        enum_parser.add_argument("-o", "--output", help="Output file to save results")
        enum_parser.add_argument("-ul", "--username_file", required=True, help="Username list file (one username per line)")
        enum_parser.add_argument("-u", "--user", help="Username for authenticated bind")

        # Brute-force
        brute_parser = ldap_subparsers.add_parser("bruteforce", help="Brute-force LDAP user credentials")
        brute_parser.add_argument("-ip", required=True, help="Target IP address")
        brute_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        brute_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        brute_parser.add_argument("-bd", "--base-dn", help="Base DN (example: dc=example,dc=com)")
        brute_parser.add_argument("-upn", "--upn-domain", help="UPN domain (example: example.com)")
        brute_parser.add_argument("-spray", action="store_true", help="Enable password spraying mode (one password across all users)")
        brute_parser.add_argument("-o", "--output", help="Output file to save valid credentials")
        brute_parser.add_argument("-cnuid", nargs='+', default=['uid', 'cn'], help="Attributes to bind with (default: uid and cn)")

        user_group = brute_parser.add_mutually_exclusive_group(required=True)
        user_group.add_argument("-ul", "--username_file", help="Username list file (required if -u not provided)")
        user_group.add_argument("-u", "--user", help="Single username to try (required if -ul not used)")

        pass_group = brute_parser.add_mutually_exclusive_group(required=True)
        pass_group.add_argument("-pl", "--password_file", help="Password list file (required if -pw not provided)")
        pass_group.add_argument("-pw", "--password", help="Single password to try (required if -pl not used)")
        

        # Write-access Test
        # ToDo: potreba otestovat
        write_parser = ldap_subparsers.add_parser("writetest", help="Test write permissions on LDAP entries")
        write_parser.add_argument("-ip", required=True, help="Target IP address")
        write_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
        write_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
        write_parser.add_argument("-u", "--user", help="Username for authenticated bind")
        write_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
        write_parser.add_argument("-bd", "--base-dn", help="Base DN (for finding entries)")
        write_parser.add_argument("-t", "--target-dn", help="Specific DN to test writing to (Dfault: objectClass=person)")
        write_parser.add_argument("-attr", "--attribute", default="sn", help="Attribute to modify (default: sn)")
        write_parser.add_argument("-val", "--value", dest="test_value", help="Custom value to write instead of default: SecurityTest123")



class LDAP(BaseModule):
    @staticmethod
    def module_args():
        return LDAPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        self.args = args 
        self.ptjsonlib = ptjsonlib
        self.results: LDAPResult | None = None

    def run(self) -> None:
        """Main SNMP execution logic"""

        self.results = LDAPResult()

        if self.args.command == "banner":
            self.results.Banner = self.ldap_banner()
        
        elif self.args.command == "search":
            self.results.Search = self.ldap_search()
        
        elif self.args.command == "userenum":
            self.results.usernames = self.ldap_enumerate_users()

        elif self.args.command == "bruteforce":
            self.results.credentials = self.ldap_bruteforce()

        elif self.args.command == "writetest":
            self.results.Writetest = self.ldap_check_write_access()
        
        else:
            ptprinthelper.ptprint("[!] Unknown command for SNMP module.")
        

    def drawLine(self):
        print ('-' * 75)

    def drawDoubleLine(self):
        print ('=' * 75)

    def write_to_file(self, message_or_messages: str | list[str]):
        """
            File Output.
        """
        with open(self.args.output_file, 'a') as f:
            if isinstance(message_or_messages, str):
                # If it's a single message, write it directly
                f.write(message_or_messages + '\n')
            elif isinstance(message_or_messages, list):
                # If it's a list of messages, iterate and write each one
                for message in message_or_messages:
                    f.write(message + '\n')

    def _text_or_file(self, text: str | None, file_path: str | None):
        """
            One domain/address or file.
        """
        if text:
            return [text.strip()]
        elif file_path:
            try:
                with open(file_path, 'r') as file:
                    return [line.strip() for line in file if line.strip()]
            except Exception as e:
                ptprinthelper.ptprint(Fore.RED + f"[!] ERROR: reading file {file_path}: {e}"+ Style.RESET_ALL)
                return []
        else:
            ptprinthelper.ptprint(Fore.RED + "[!] ERROR: Neither text nor file input provided."+ Style.RESET_ALL)
            return []
        
    def print_title1(self, title):
                ptprinthelper.ptprint(Fore.MAGENTA + f"\n[*] {title}"+ Style.RESET_ALL)
                ptprinthelper.ptprint('-' * (len(title) + 6))
    
    def print_title2(self, title):
                ptprinthelper.ptprint(Fore.CYAN + f"\n[*] {title}"+ Style.RESET_ALL)
                ptprinthelper.ptprint('-' * (len(title) + 6))

    def print_subtitle(self, title):
        ptprinthelper.ptprint(Fore.MAGENTA + f"  - {title}" + Style.RESET_ALL)

    def print_list(self, title, items):
        self.print_title1(title)
        if items:
            for item in items:
                ptprinthelper.ptprint(f"  - {item}")
        else:
            ptprinthelper.ptprint(Fore.RED + " No data found."+ Style.RESET_ALL)

    def create_ldap_connection(self):
        """
        Establishes an LDAP connection and returns the connection object.
        """
        try:
            server = Server(self.args.ip, port=self.args.port, use_ssl=self.args.use_ssl, get_info=ALL)
            if self.args.user and self.args.password:
                conn = Connection(server, user=self.args.user, password=self.args.password, auto_bind=True)
            else:
                conn = Connection(server, auto_bind=True)

            if not conn.bound:
                ptprinthelper.ptprint(Fore.RED + "[-] Bind failed." + Style.RESET_ALL)
                return None
            return server, conn

        except Exception as e:
            ptprinthelper.ptprint(Fore.RED + f"[!] ERROR: {e}" + Style.RESET_ALL)
            return None

    def ldap_banner(self) -> dict:
        """
        Retrieves and displays detailed LDAP server information.
        """

        self.drawDoubleLine()
        ptprinthelper.ptprint(Fore.CYAN + f"[+] Retrieving LDAP banner information at {self.args.ip}:{self.args.port} (SSL: {self.args.use_ssl})"+ Style.RESET_ALL)
        self.drawDoubleLine()

        connection = self.create_ldap_connection()
        if connection:
            server, conn = connection
            server_info = server.info
        else:
            return None
        
        if not conn.bind() ==True:
            return None

        if self.args.output_file:
                self.write_to_file(str(server_info)) 

        result = {
            "Supported LDAP Versions": server_info.supported_ldap_versions,
            "Naming Contexts": server_info.naming_contexts,
            "Supported Controls": server_info.supported_controls,
            "Supported Extensions": server_info.supported_extensions,
            "Supported Features": server_info.supported_features,
            "Supported SASL Mechanisms": server_info.supported_sasl_mechanisms,
            "Schema Entry": getattr(server_info, 'schema_entry', None),
            "Vendor Name": getattr(server_info, 'vendor_name', None),
            "Vendor Version": getattr(server_info, 'vendor_version', None),
            "Other Attributes": getattr(server_info, 'other', {}),
        }

        # Print output
        self.print_list("Supported LDAP Versions", result["Supported LDAP Versions"])
        self.print_list("Naming Contexts", result["Naming Contexts"])
        self.print_list("Supported Controls", result["Supported Controls"])
        self.print_list("Supported Extensions", result["Supported Extensions"])
        self.print_list("Supported Features", result["Supported Features"])
        self.print_list("Supported SASL Mechanisms", result["Supported SASL Mechanisms"])

        if result["Schema Entry"]:
            self.print_title1("Schema Entry")
            ptprinthelper.ptprint(f"  - {result['Schema Entry']}")
            
        if result["Vendor Name"]:
            self.print_title1("Vendor Name")
            ptprinthelper.ptprint(f"  - {result['Vendor Name']}")  

        if result["Vendor Version"]:
            self.print_title1("Vendor Version")
            ptprinthelper.ptprint(f"  - {result['Vendor Version']}")



        self.print_title1("Other Attributes")
        other = result["Other Attributes"]
        if other:
            for key, value in other.items():
                self.print_subtitle(key.capitalize())
                if not value:
                    ptprinthelper.ptprint(Fore.RED + "    No data found."+ Style.RESET_ALL)
                elif isinstance(value, list):
                    for item in value:
                        ptprinthelper.ptprint(f"    {item}")
                else:
                    ptprinthelper.ptprint(f"    {value}")

        else:
            ptprinthelper.ptprint(Fore.RED + " No data found."+ Style.RESET_ALL)
            
        return result

    def ldap_search(self) -> list[dict]:
        """
        Performs an LDAP search with a custom filter and optional attribute list.
        """

        self.drawDoubleLine()
        ptprinthelper.ptprint(Fore.CYAN + f"[+] Search result for filter: {self.args.ldap_filter} in base: {self.args.base_dn}" + Style.RESET_ALL)
        self.drawDoubleLine()

        connection = self.create_ldap_connection()

        if not connection:
            return []
        
        server, conn = connection

        if not self.args.base_dn:
            if server.info.naming_contexts:
                base_dn = server.info.naming_contexts[0]
                ptprinthelper.ptprint(Fore.YELLOW + f"[!] No base_dn provided. Using detected: {base_dn}" + Style.RESET_ALL)
            else:
                ptprinthelper.ptprint(Fore.RED + "[!] Base DN could not be determined automatically." + Style.RESET_ALL)
                ptprinthelper.ptprint(Fore.RED + "[!] Please specify a base_dn manually. Otherwise, the search cannot continue." + Style.RESET_ALL)
                return []
            
        else: base_dn = self.args.base_dn

        attributes = self.args.attributes if self.args.attributes else ['*']

        conn.search(
            search_base=base_dn,
            search_filter=self.args.ldap_filter,
            search_scope=SUBTREE,
            attributes=attributes
        )

        results = []

        for entry in conn.entries:
                self.print_ldapsearch(entry, attributes)

                results.append({
                    "dn": entry.entry_dn,
                    "attributes": entry.entry_attributes_as_dict
                })
        
        # If output file path is specified, write the retrieved server information to the file
        if self.args.output_file:
            self.write_to_file(str(conn.entries))
                
        conn.unbind()
        return results
  

    def print_ldapsearch(self, entry, attributes):
        """
        Nicely formats and prints LDAP entry details with selected attributes.
        """

        ptprinthelper.ptprint('')
        self.drawLine()
        ptprinthelper.ptprint(Fore.MAGENTA + "[*] Entry DN" + Style.RESET_ALL)
        self.drawLine()
        ptprinthelper.ptprint(f"{entry.entry_dn}\n")


        if not attributes or attributes == ['*']:
            object_classes = entry['objectClass'].value if 'objectClass' in entry else []
            main_class = object_classes[1] if len(object_classes) > 1 else object_classes[0] if object_classes else "N/A"

            self.print_title1("Object Class Overview")

            ptprinthelper.ptprint(f"Main Class     : {main_class}")
            ptprinthelper.ptprint("All Classes    : " + "-".join(object_classes) + "\n")

        self.print_title1("Attributes")

        for attr in entry.entry_attributes:
            if attr == "objectClass":
                continue
            val = entry[attr].value
            if not val:
                val_display = "N/A"
            else:
                val_display = ", ".join(val) if isinstance(val, list) else str(val)
            ptprinthelper.ptprint(Fore.MAGENTA + f"{attr.capitalize():<30}" + Style.RESET_ALL + f": {val_display}")


    def ldap_enumerate_users(self) -> list[str]:
        """
        Enumerates valid usernames by using the existing ldap_search function.
        """

        self.drawDoubleLine()
        ptprinthelper.ptprint(Fore.CYAN + f"[+] Starting LDAP username enumeration on {self.args.ip}:{self.args.port} (SSL: {self.args.use_ssl})" + Style.RESET_ALL)
        self.drawDoubleLine()

        if not self.args.username_file:
            ptprinthelper.ptprint(Fore.RED + "[!] No username list provided for enumeration." + Style.RESET_ALL)
            return []
        
        usernames = self._text_or_file(None, self.args.username_file)
        valid_users = []

        connection = self.create_ldap_connection()
        if connection:
            server, conn = connection
        else:
            return []

        if not self.args.base_dn:
            if server.info.naming_contexts:
                base_dn = server.info.naming_contexts[0]
                ptprinthelper.ptprint(Fore.YELLOW + f"[!] No base_dn provided. Using detected: {base_dn}" + Style.RESET_ALL)
            else:
                ptprinthelper.ptprint(Fore.RED + "[!] Base DN could not be determined automatically." + Style.RESET_ALL)
                ptprinthelper.ptprint(Fore.RED + "[!] Please specify a base_dn manually. Otherwise, the search cannot continue." + Style.RESET_ALL)
                return []
        else: base_dn = self.args.base_dn

        try: 
            attributes = ['*']   

            for username in usernames:
                ldap_filter = f"(&({self.args.search_attribute}={username}))"

                conn.search(
                    search_base=base_dn,
                    search_filter=ldap_filter,
                    search_scope=SUBTREE,
                    attributes=attributes)
                
                found = len(conn.entries) > 0  #True if found, False otherwise

                if found:
                    ptprinthelper.ptprint(Fore.GREEN + f"SUCCESS: {username}" + Style.RESET_ALL)
                    valid_users.append(username)
                else:
                    ptprinthelper.ptprint(f"FAIL: {username}")

            conn.unbind()

            if valid_users:

                # If output file path is specified, write the retrieved server information to the file
                if self.args.output_file:
                    self.write_to_file(valid_users)

                self.print_title2("Valid users found:")
                for u in valid_users:
                    ptprinthelper.ptprint(f"  - {u}")
            else:
                ptprinthelper.ptprint(Fore.RED + "[!] No valid users found." + Style.RESET_ALL)

            return valid_users
            
            
        except Exception as e:
            ptprinthelper.ptprint(Fore.RED + f"[!] ERROR: {e}" + Style.RESET_ALL)
            return []
        
        
       

    def ldap_bruteforce(self) -> list[Credential]:
        """
        Attempts to brute-force LDAP credentials using provided usernames and passwords.
        """

        self.drawDoubleLine()
        ptprinthelper.ptprint(Fore.CYAN + f"[+] Starting LDAP brute-force on {self.args.ip}:{self.args.port} (SSL: {self.args.use_ssl})" + Style.RESET_ALL)
        self.drawDoubleLine()

        usernames = self._text_or_file(self.args.user, self.args.username_file)
        passwords = self._text_or_file(self.args.password, self.args.password_file)

        # Spray logic
        if self.args.spray:
            creds = [Credential(u, p) for p in passwords for u in usernames]
        else:
            creds = [Credential(u, p) for u in usernames for p in passwords]

        valid_credentials = []
        if not usernames or not passwords:
            ptprinthelper.ptprint(Fore.RED + "[!] Usernames or passwords list is empty." + Style.RESET_ALL)
            return
        
        if not self.args.base_dn and not self.args.upn_domain:
            ptprinthelper.ptprint(Fore.RED + "[!] No base_dn provided." + Style.RESET_ALL)
            ptprinthelper.ptprint(Fore.YELLOW + "[!] Proceeding with simple username-only bind. Success is unlikely unless the server accepts plain usernames." + Style.RESET_ALL)
        
        for cred in creds:
            for i in self.args.cn_uid:    
                try:
                    if self.args.base_dn:
                        bind_dn = f"{i}={cred.username},{self.args.base_dn}"
                    elif self.args.upn_domain:
                        bind_dn = f"{cred.username}@{self.args.upn_domain}"
                    else:
                        bind_dn = cred.username  # Simple username only
                   
                    server = Server(self.args.ip, port=self.args.port, use_ssl=self.args.use_ssl, get_info=ALL)
                    conn = Connection(server, user=bind_dn, password=cred.password, auto_bind=True)
                    if conn.bound:
                        ptprinthelper.ptprint(Fore.GREEN + f"SUCCESS: {bind_dn}:{cred.password}" + Style.RESET_ALL)
                        valid_credentials.append(Credential(username=bind_dn, password=cred.password))
                        conn.unbind()
                except Exception as e:
                    err_msg = str(e).lower()
                    if "invalidcredentials" in err_msg:
                        ptprinthelper.ptprint(f"FAIL: {bind_dn}:{cred.password}")
                    else:
                        ptprinthelper.ptprint(Fore.RED + f"[!] ERROR for {bind_dn}:{cred.password} -> {e}" + Style.RESET_ALL)

        if valid_credentials:

            # If output file path is specified, write the retrieved server information to the file
            if self.args.output_file:
                results = [f"Username: {cred.username}, Password: {cred.password}" for cred in valid_credentials]
                self.write_to_file(results)

            self.print_title2("Valid credentials found:")
            for user, password in valid_credentials:
                ptprinthelper.ptprint(f"Username: {user:<50} Password: {password}")

            return valid_credentials
        
        else:
            ptprinthelper.ptprint(Fore.RED + "[-] No valid credentials were found." + Style.RESET_ALL)

            return []



    def ldap_check_write_access(self):
        """
        Tests LDAP write access by attempting to modify a specified attribute.
        """
        self.drawDoubleLine()
        ptprinthelper.ptprint(Fore.CYAN + f"[+] Testing write access on {self.args.ip}:{self.args.port} (SSL: {self.args.use_ssl})" + Style.RESET_ALL)
        self.drawDoubleLine()

        connection = self.create_ldap_connection()
        if not connection:
            return
        server, conn = connection

        try:
            # Find a candidate DN if not provided
            if not self.args.target_dn:
                base_dn = server.info.naming_contexts[0] if server.info.naming_contexts else ''
                conn.search(base_dn, '(objectClass=person)', attributes='sn', size_limit=1)
                if not conn.entries:
                    ptprinthelper.ptprint(Fore.RED + "[!] Could not find a modifiable entry (objectClass=person)." + Style.RESET_ALL)
                    return []
                self.args.target_dn = conn.entries[0].entry_dn
                ptprinthelper.ptprint(f"Target dn: {self.args.target_dn}")

            if self.args.test_value:
                test_value = self.args.test_value
            else:
                test_value = 'SecurityTest123'

            # Attempt modification
            success = conn.modify(
                dn=self.args.target_dn,
                changes={self.args.attribute: [(MODIFY_REPLACE, [test_value])]}
            )

            if success:
                ptprinthelper.ptprint(Fore.GREEN + f"[+] SUCCESS: Write access confirmed on '{self.args.attribute}' at {self.args.target_dn}" + Style.RESET_ALL)
                ptprinthelper.ptprint(Fore.YELLOW + "[!] Note: Attribute was modified for testing purposes. Don't forget to revert it back if necessary." + Style.RESET_ALL)
                atribute = self.args.attribute
                username  = self.args.user
                password = self.args.password
                result = TestWriteResult(
                    target_dn=self.args.target_dn,
                    atribute=atribute,
                    value= test_value,
                    credentials=f"{username}:{password}"
                )
                return result

            else:
                ptprinthelper.ptprint(Fore.RED + f"[-] FAILED: No write access to '{self.args.attribute}' at {self.args.target_dn}" + Style.RESET_ALL)
                ptprinthelper.ptprint(Fore.RED + f"    Details: {conn.result['description']} - {conn.result.get('message', '')}" + Style.RESET_ALL)
                return []
        except Exception as e:
            ptprinthelper.ptprint(Fore.RED + f"[!] ERROR: {e}" + Style.RESET_ALL)
        finally:
            conn.unbind()

    def output(self) -> None:
        """
        Banner: Optional[dict] = None
        Search: Optional[list[dict]] = None
        usernames: Optional[list[str]] = None
        credentials: Optional[list[Credential]] = None
        Writetest: Optional[TestWriteResult] = None

        WeakUsername = "PTV-LDAP-WEAKUSERNAME"
        WeakCredentials = "PTV-LDAP-WEAKCREDENTIALS"
        Write = "PTV-LDAP-WRITEACCESS"
        """

        def credentials_to_string(creds: List[Credential]) -> str:
            return ", ".join(
                f"{c.username or 'None'}:{c.password or 'None'}"
                for c in creds
            )
        def write_results_to_string(result: TestWriteResult) -> str:
            return f"{result.target_dn or 'None'}-{result.atribute or 'None'}-{result.value}-{result.credentials}"

        if (self.results.usernames != None):
            if len(self.results.usernames) != 0:
                self.ptjsonlib.add_vulnerability(VULNS.WeakUsername.value, "Searching for usernames", ",".join(self.results.usernames))
        

        if (self.results.credentials != None):
            if len(self.results.credentials) != 0:
                cred_str = credentials_to_string(self.results.credentials)
                self.ptjsonlib.add_vulnerability(VULNS.WeakCredentials.value, "Bruteforcing LDAP credentials", cred_str) 

        if (self.results.Writetest != None):
            if len(self.results.Writetest) != 0:
                value_str = write_results_to_string(self.results.Writetest)
                self.ptjsonlib.add_vulnerability(VULNS.Write.value, "Testing write access", value_str)

        self.ptprint(self.ptjsonlib.get_result_json(), json=True)
