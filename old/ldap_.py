from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from colorama import Fore, Style, init
from typing import  NamedTuple
import argparse 
import sys

class Credential(NamedTuple):
    username: str
    password: str

class LDAP:
    def __init__(self, 
                 ip: str, 
                 port:int = 389, 
                 use_ssl:bool = False, 
                 spray:bool = False,
                 output_file:str = None, 
                 base_dn:str = None,
                 upn_domain:str=None,
                 username_file:str = None,
                 password_file:str = None,
                 user:str = None,
                 password:str = None):
        
        self.ip = ip
        self.port = port
        self.use_ssl = use_ssl
        self.spray = spray
        self.output_file = output_file
        self.base_dn = base_dn
        self.upn_domain = upn_domain

        self.user = user
        self.password = password
        self.username_file = username_file
        self.password_file = password_file

    def run(self):
        # self.ldap_banner()
        # self.ldap_search()
        # self.ldap_bruteforce()
        # self.ldap_enumerate_users()
        self.ldap_check_write_access()

    def drawLine(self):
        print ('-' * 75)

    def drawDoubleLine(self):
        print ('=' * 75)

    def write_to_file(self, message_or_messages: str | list[str]):
        """
            File Output.
        """
        with open(self.output_file, 'a') as f:
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
                print(Fore.RED + f"[!] ERROR: reading file {file_path}: {e}"+ Style.RESET_ALL)
                return []
        else:
            print(Fore.RED + "[!] ERROR: Neither text nor file input provided."+ Style.RESET_ALL)
            return []
        
    def print_title1(self, title):
                print(Fore.MAGENTA + f"\n[*] {title}"+ Style.RESET_ALL)
                print('-' * (len(title) + 6))
    
    def print_title2(self, title):
                print(Fore.CYAN + f"\n[*] {title}"+ Style.RESET_ALL)
                print('-' * (len(title) + 6))

    def print_subtitle(self, title):
        print(Fore.MAGENTA + f"  - {title}" + Style.RESET_ALL)

    def print_list(self, title, items):
        self.print_title1(title)
        if items:
            for item in items:
                print(f"  - {item}")
        else:
            print(Fore.RED + " No data found."+ Style.RESET_ALL)

    def create_ldap_connection(self):
        """
        Establishes an LDAP connection and returns the connection object.
        """
        try:
            server = Server(self.ip, port=self.port, use_ssl=self.use_ssl, get_info=ALL)
            if self.user and self.password:
                conn = Connection(server, user=self.user, password=self.password, auto_bind=True)
            else:
                conn = Connection(server, auto_bind=True)

            if not conn.bound:
                print(Fore.RED + "[-] Bind failed." + Style.RESET_ALL)
                return None
            return server, conn

        except Exception as e:
            print(Fore.RED + f"[!] ERROR: {e}" + Style.RESET_ALL)
            return None

    def ldap_banner(self):
        """
        Retrieves and displays detailed LDAP server information.
        """

        self.drawDoubleLine()
        print(Fore.CYAN + f"[+] Retrieving LDAP banner information at {self.ip}:{self.port} (SSL: {self.use_ssl})"+ Style.RESET_ALL)
        self.drawDoubleLine()

        connection = self.create_ldap_connection()
        if connection:
            server, conn = connection
            server_info = server.info
        else:
            return 
        if conn.bind() ==True:

            # If output file path is specified, write the retrieved server information to the file
            if self.output_file:
                self.write_to_file(str(server_info))    
            self.print_list("Supported LDAP Versions", server_info.supported_ldap_versions)
            self.print_list("Naming Contexts", server_info.naming_contexts)
            self.print_list("Supported Controls", server_info.supported_controls)
            self.print_list("Supported Extensions", server_info.supported_extensions)
            self.print_list("Supported Features", server_info.supported_features)
            self.print_list("Supported SASL Mechanisms", server_info.supported_sasl_mechanisms)
            
            schema_entry = getattr(server_info, 'schema_entry', None)
            if schema_entry:
                self.print_title1("Schema Entry")
                print(f"  - {schema_entry}")

            vendor_name = getattr(server_info, 'vendor_name', None)
            if vendor_name:
                self.print_title1("Vendor Name")
                print(f"  - {vendor_name}")

            vendor_version = getattr(server_info, 'vendor_version', None)
            if vendor_version:
                self.print_title1("Vendor Version")
                print(f"  - {vendor_version}")

            self.print_title1("Other Attributes")
            other = getattr(server_info, 'other', 'N/A')
            if other:
                for key, value in other.items():
                    self.print_subtitle(key.capitalize())
                    if not value:
                        print(Fore.RED + "    No data found."+ Style.RESET_ALL)
                    elif isinstance(value, list):
                        for item in value:
                            print(f"    {item}")
                    else:
                        print(f"    {value}")

            else:
                print(Fore.RED + " No data found."+ Style.RESET_ALL)
            

    def ldap_search(self, ldap_filter='(ObjectClass=*)', attributes=None):
        """
        Performs an LDAP search with a custom filter and optional attribute list.
        """

        self.drawDoubleLine()
        print(Fore.CYAN + f"[+] Search result for filter: {ldap_filter} in base: {self.base_dn}" + Style.RESET_ALL)
        self.drawDoubleLine()

        connection = self.create_ldap_connection()
        if connection:
            server, conn = connection

            if not self.base_dn:
                if server.info.naming_contexts:
                    base_dn = server.info.naming_contexts[0]
                    print(Fore.YELLOW + f"[!] No base_dn provided. Using detected: {base_dn}" + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[!] Base DN could not be determined automatically." + Style.RESET_ALL)
                    print(Fore.RED + "[!] Please specify a base_dn manually. Otherwise, the search cannot continue." + Style.RESET_ALL)
                    return
                
            else: base_dn = self.base_dn

            if not attributes:
                attributes = ['*']

            conn.search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )

            # If output file path is specified, write the retrieved server information to the file
            if self.output_file:
                self.write_to_file(str(conn.entries))

            for entry in conn.entries:
                    self.print_ldapsearch(entry, attributes)
                    
            conn.unbind()
        else:
            return

    def print_ldapsearch(self, entry, attributes):
        """
        Nicely formats and prints LDAP entry details with selected attributes.
        """

        print()
        self.drawLine()
        print(Fore.MAGENTA + "[*] Entry DN" + Style.RESET_ALL)
        self.drawLine()
        print(f"{entry.entry_dn}\n")


        if not attributes or attributes == ['*']:
            object_classes = entry['objectClass'].value if 'objectClass' in entry else []
            main_class = object_classes[1] if len(object_classes) > 1 else object_classes[0] if object_classes else "N/A"

            self.print_title1("Object Class Overview")

            print(f"Main Class     : {main_class}")
            print("All Classes    : " + "-".join(object_classes) + "\n")

        self.print_title1("Attributes")

        for attr in entry.entry_attributes:
            if attr == "objectClass":
                continue
            val = entry[attr].value
            if not val:
                val_display = "N/A"
            else:
                val_display = ", ".join(val) if isinstance(val, list) else str(val)
            print(Fore.MAGENTA + f"{attr.capitalize():<30}" + Style.RESET_ALL + f": {val_display}")


    def ldap_enumerate_users(self, search_attribute='uid'):
        """
        Enumerates valid usernames by using the existing ldap_search function.
        """

        self.drawDoubleLine()
        print(Fore.CYAN + f"[+] Starting LDAP username enumeration on {self.ip}:{self.port} (SSL: {self.use_ssl})" + Style.RESET_ALL)
        self.drawDoubleLine()

        if not self.username_file:
            print(Fore.RED + "[!] No username list provided for enumeration." + Style.RESET_ALL)
            return
        
        usernames = self._text_or_file(None, self.username_file)
        valid_users = []

        connection = self.create_ldap_connection()
        if connection:
            server, conn = connection
        else:
            return

        if not self.base_dn:
            if server.info.naming_contexts:
                base_dn = server.info.naming_contexts[0]
                print(Fore.YELLOW + f"[!] No base_dn provided. Using detected: {base_dn}" + Style.RESET_ALL)
            else:
                print(Fore.RED + "[!] Base DN could not be determined automatically." + Style.RESET_ALL)
                print(Fore.RED + "[!] Please specify a base_dn manually. Otherwise, the search cannot continue." + Style.RESET_ALL)
                return
        else: base_dn = self.base_dn

        try: 
            attributes = ['*']   

            for username in usernames:
                ldap_filter = f"(&({search_attribute}={username}))"

                conn.search(
                    search_base=base_dn,
                    search_filter=ldap_filter,
                    search_scope=SUBTREE,
                    attributes=attributes)
                
                print(conn.entries)
                found = len(conn.entries) > 0  #True if found, False otherwise
        
                if found:
                    print(Fore.GREEN + f"SUCCESS: {username}" + Style.RESET_ALL)
                    valid_users.append(username)
                else:
                    print(f"FAIL: {username}")

            conn.unbind()

            if valid_users:

                # If output file path is specified, write the retrieved server information to the file
                if self.output_file:
                    self.write_to_file(valid_users)

                self.print_title2("Valid users found:")
                for u in valid_users:
                    print(f"  - {u}")
            else:
                print(Fore.RED + "[!] No valid users found." + Style.RESET_ALL)
            
            
        except Exception as e:
            print(Fore.RED + f"[!] ERROR: {e}" + Style.RESET_ALL)
            return False
        
        
       

    def ldap_bruteforce(self, cn_uid = ['uid', 'cn']):
        """
        Attempts to brute-force LDAP credentials using provided usernames and passwords.
        """

        self.drawDoubleLine()
        print(Fore.CYAN + f"[+] Starting LDAP brute-force on {self.ip}:{self.port} (SSL: {self.use_ssl})" + Style.RESET_ALL)
        self.drawDoubleLine()

        usernames = self._text_or_file(self.user, self.username_file)
        passwords = self._text_or_file(self.password, self.password_file)

        # Spray logic
        if self.spray:
            creds = [Credential(u, p) for p in passwords for u in usernames]
        else:
            creds = [Credential(u, p) for u in usernames for p in passwords]

        valid_credentials = []
        if not usernames or not passwords:
            print(Fore.RED + "[!] Usernames or passwords list is empty." + Style.RESET_ALL)
            return
        
        if not self.base_dn and not self.upn_domain:
            print(Fore.RED + "[!] No base_dn provided." + Style.RESET_ALL)
            print(Fore.YELLOW + "[!] Proceeding with simple username-only bind. Success is unlikely unless the server accepts plain usernames." + Style.RESET_ALL)
        
        for cred in creds:
            for i in cn_uid:    
                try:
                    if self.base_dn:
                        bind_dn = f"{i}={cred.username},{self.base_dn}"
                    elif self.upn_domain:
                        bind_dn = f"{cred.username}@{self.upn_domain}"
                    else:
                        bind_dn = cred.username  # Simple username only
                   
                    server = Server(self.ip, port=self.port, use_ssl=self.use_ssl, get_info=ALL)
                    conn = Connection(server, user=bind_dn, password=cred.password, auto_bind=True)
                    if conn.bound:
                        print(Fore.GREEN + f"SUCCESS: {bind_dn}:{cred.password}" + Style.RESET_ALL)
                        valid_credentials.append(Credential(username=bind_dn, password=cred.password))
                        conn.unbind()
                except Exception as e:
                    err_msg = str(e).lower()
                    if "invalidcredentials" in err_msg:
                        print(f"FAIL: {bind_dn}:{cred.password}")
                    else:
                        print(Fore.RED + f"[!] ERROR for {bind_dn}:{cred.password} -> {e}" + Style.RESET_ALL)

        if valid_credentials:

            # If output file path is specified, write the retrieved server information to the file
            if self.output_file:
                results = [f"Username: {cred.username}, Password: {cred.password}" for cred in valid_credentials]
                self.write_to_file(results)

            self.print_title2("Valid credentials found:")
            for user, password in valid_credentials:
                print(f"Username: {user:<50} Password: {password}")
        else:
            print(Fore.RED + "[-] No valid credentials were found." + Style.RESET_ALL)


    def ldap_check_write_access(self, target_dn=None, attribute='sn', test_value=None):
        """
        Tests LDAP write access by attempting to modify a specified attribute.
        """
        self.drawDoubleLine()
        print(Fore.CYAN + f"[+] Testing write access on {self.ip}:{self.port} (SSL: {self.use_ssl})" + Style.RESET_ALL)
        self.drawDoubleLine()

        connection = self.create_ldap_connection()
        if not connection:
            return
        server, conn = connection

        try:
            # Find a candidate DN if not provided
            if not target_dn:
                base_dn = server.info.naming_contexts[0] if server.info.naming_contexts else ''
                conn.search(base_dn, '(objectClass=person)', attributes='sn', size_limit=1)
                if not conn.entries:
                    print(Fore.RED + "[!] Could not find a modifiable entry (objectClass=person)." + Style.RESET_ALL)
                    return
                target_dn = conn.entries[0].entry_dn
                print(f"Target dn: {target_dn}")

            if not test_value:
                test_value = 'SecurityTest123'

            # Attempt modification
            success = conn.modify(
                dn=target_dn,
                changes={attribute: [(MODIFY_REPLACE, [test_value])]}
            )

            if success:
                print(Fore.GREEN + f"[+] SUCCESS: Write access confirmed on '{attribute}' at {target_dn}" + Style.RESET_ALL)
                print(Fore.YELLOW + "[!] Note: Attribute was modified for testing purposes. Don't forget to revert it back if necessary." + Style.RESET_ALL)

            else:
                print(Fore.RED + f"[-] FAILED: No write access to '{attribute}' at {target_dn}" + Style.RESET_ALL)
                print(Fore.RED + f"    Details: {conn.result['description']} - {conn.result.get('message', '')}" + Style.RESET_ALL)

        except Exception as e:
            print(Fore.RED + f"[!] ERROR: {e}" + Style.RESET_ALL)
        finally:
            conn.unbind()


def main():  
    parser = argparse.ArgumentParser( description="LDAP Tool")

    subparsers = parser.add_subparsers(dest="command", help="Select the functionality to execute")
    
    # Banner grabbing
    banner_parser = subparsers.add_parser("banner", help="Retrieve LDAP server banner information")
    banner_parser.add_argument("-ip", required=True, help="Target IP address")
    banner_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
    banner_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
    banner_parser.add_argument("-u", "--user", help="Username for authenticated bind (format: cn=admin,dc=example,dc=com OR user@example.com)")
    banner_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
    banner_parser.add_argument("-o", "--output", help="Output file to save results")

    # LDAP search
    search_parser = subparsers.add_parser("search", help="Perform LDAP search query")
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
    enum_parser = subparsers.add_parser("userenum", help="Enumerate valid LDAP users")
    enum_parser.add_argument("-ip", required=True, help="Target IP address")
    enum_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
    enum_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
    enum_parser.add_argument("-u", "--user", help="Username for authenticated bind")
    enum_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
    enum_parser.add_argument("-bd", "--base-dn", help="Base DN (recommended, but can try to auto-detect)")
    enum_parser.add_argument("-ul", "--userlist", required=True, help="Username list file (one username per line)")
    enum_parser.add_argument("-o", "--output", help="Output file to save results")

    # Brute-force
    brute_parser = subparsers.add_parser("bruteforce", help="Brute-force LDAP user credentials")
    brute_parser.add_argument("-ip", required=True, help="Target IP address")
    brute_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
    brute_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
    brute_parser.add_argument("-ul", "--userlist", help="Username list file (required if -u not provided)")
    brute_parser.add_argument("-pl", "--passlist", help="Password list file (required if -pw not provided)")
    brute_parser.add_argument("-u", "--user", help="Single username to try (required if -ul not used)")
    brute_parser.add_argument("-pw", "--password", help="Single password to try (required if -pl not used)")
    brute_parser.add_argument("-bd", "--base-dn", help="Base DN (example: dc=example,dc=com)")
    brute_parser.add_argument("-upn", "--upn-domain", help="UPN domain (example: example.com)")
    brute_parser.add_argument("-spray", action="store_true", help="Enable password spraying mode (one password across all users)")
    brute_parser.add_argument("-o", "--output", help="Output file to save valid credentials")
    brute_parser.add_argument("-cnuid", nargs='+', default=['uid', 'cn'], help="Attributes to bind with (default: uid and cn)")

    # Write-access Test
    # ToDo: potreba otestovat
    write_parser = subparsers.add_parser("writetest", help="Test write permissions on LDAP entries")
    write_parser.add_argument("-ip", required=True, help="Target IP address")
    write_parser.add_argument("-p", "--port", type=int, default=389, help="Target port (default: 389)")
    write_parser.add_argument("--ssl", action="store_true", help="Use SSL for connection")
    write_parser.add_argument("-u", "--user", help="Username for authenticated bind")
    write_parser.add_argument("-pw", "--password", help="Password for authenticated bind")
    write_parser.add_argument("-bd", "--base-dn", help="Base DN (for finding entries)")
    write_parser.add_argument("-t", "--target-dn", help="Specific DN to test writing to (Dfault: objectClass=person)")
    write_parser.add_argument("-attr", "--attribute", default="sn", help="Attribute to modify (default: sn)")
    write_parser.add_argument("-val", "--value", dest="test_value", help="Custom value to write instead of default: SecurityTest123")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Mapping commands to methods
    ldap_tool = LDAP(
        ip=args.ip,
        port=args.port,
        use_ssl=args.ssl,
        spray=getattr(args,"spray", False),
        user=args.user,
        password=args.password,
        output_file=getattr(args, "output", False),
        base_dn=getattr(args, "base_dn", None),
        username_file=getattr(args, "userlist", None),
        password_file=getattr(args, "passlist", None),
        upn_domain=getattr(args, "upn_domain", None)
    )

    if args.command == "banner":
        ldap_tool.ldap_banner()
    elif args.command == "search":
        ldap_tool.ldap_search(ldap_filter=args.filter, attributes=args.attributes)
    elif args.command == "userenum":
        ldap_tool.ldap_enumerate_users()
    elif args.command == "bruteforce":
        if args.user and args.userlist:
            print(Fore.RED + "[!] You cannot use both -u and -ul. Choose either a single username or a user list." + Style.RESET_ALL)
            return
        if not args.user and not args.userlist:
            print(Fore.RED + "[!] You must specify either -u or -ul." + Style.RESET_ALL)
            return

        if args.password and args.passlist:
            print(Fore.RED + "[!] You cannot use both -pw and -pl. Choose either a single password or a password list." + Style.RESET_ALL)
            return
        if not args.password and not args.passlist:
            print(Fore.RED + "[!] You must specify either -pw or -pl." + Style.RESET_ALL)
            return
        ldap_tool.ldap_bruteforce(cn_uid=args.cnuid)
    elif args.command == "writetest":
        ldap_tool.ldap_check_write_access(target_dn=args.target_dn, attribute=args.attribute, test_value=args.value)
    else:
        print("[!] Unknown command.")
        parser.print_help()

if __name__ == '__main__':
    main()

    # ldap.forumsys.com testovaci
    # 61.221.84.77 (dn = dc=cqure, dc=net) nejaka testovaci
    # 192.168.253.128 moje
    # ipa.demo1.freeipa.org testovaci (uz nefunguje)
    # 217.30.70.204 ip ze shodanu