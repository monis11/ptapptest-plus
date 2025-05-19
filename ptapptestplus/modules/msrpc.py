import argparse
from dataclasses import dataclass
from enum import Enum
from impacket.dcerpc.v5 import epm, transport
from impacket import uuid
from impacket.dcerpc.v5 import mgmt
from impacket.dcerpc.v5.epm import KNOWN_UUIDS
from impacket.smbconnection import SMBConnection

from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out


class VULNS(Enum):
    # WeakCommunityName = "PTV-SNMPv2-WEAKCOMMUNITYNAME"
    # WeakUsername = "PTV-SNMPv3-WEAKUSERNAME"
    # WeakCredentials = "PTV-SNMPv3-WEAKCREDENTIALS"
    # Write_2 = "PTV-SNMPv2-WRITEACCESS"
    # Write_3 = "PTV-SNMPv3-WRITEACCESS"
    # Readmib_3 = "PTV-SNMPv3-READINGMIB"
    # Readmib_2 = "PTV-SNMPv3-READINGMIB"

class Credential(NamedTuple):
    username: str | None
    password: str | None

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

@dataclass
# class SNMPResult:
#     EpmapEndpoints: Optional[dict] = None
#     MgmtEndpoints: Optional[List[str]] = None
#     Pipes: Optional[List[str]] = None
#     PipesCreds: Optional[List[Credential]] = None

#     Writetest3: Optional[List[WriteTestResult]] = None
#     Writetest2: Optional[List[WriteTestResult]] = None
#     Bulk2: Optional[str] = None
#     Bulk3: Optional[str] = None

class MSRPCArgs(BaseArgs):
    ip: str
    port:int = 135 
    pipes:list = None
    username:str = None
    password:str = None
    username_file:str = None
    password_file:str = None
    pipe:str | None
    domain: str | None


    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of SNMP arguments"""

        examples = """example usage:
    ptapptest-plus snmp detection --ip 192.168.1.1 --port 161
    ptapptest-plus snmp snmpv2-brute --community-file communities.txt --ip 192.168.1.1 --port 161
    ptapptest-plus snmp snmpv3-brute --username-file users.txt --password-file passwords.txt --ip 192.168.1.1 --port 161"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError
        
class MSRPC(BaseModule):
    @staticmethod
    def module_args():
        return MSRPCArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        self.args = args  # type: SNMPArgs
        self.ptjsonlib = ptjsonlib
        self.results: MSRPCesult | None = None

    def run(self) -> None:
        """Main MSRPC execution logic"""

        self.results = MSRPCResult()











    def enumerate_epm_endpoints(self) -> dict:

        try:
            rpctransport = transport.DCERPCTransportFactory(f'ncacn_ip_tcp:{self.args.ip}[{self.args.port}]')

            # Connection 
            dce = rpctransport.get_dce_rpc()
            dce.connect()

            # Enumeration trough all endpoints registrated on the machine's Endpoint Mapper
            entries = epm.hept_lookup(None, dce=dce)

            tmp_endpoints = {}

            for entry in entries:
                binding = epm.PrintStringBinding(entry['tower']['Floors'])
                tmpUUID = str(entry['tower']['Floors'][0])
                

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
                ptprinthelper.ptprint("Protocol: %s " % tmp_endpoints[endpoint]['Protocol'])
                ptprinthelper.ptprint("Provider: %s " % tmp_endpoints[endpoint]['EXE'])
                ptprinthelper.ptprint("UUID    : %s %s" % (endpoint, tmp_endpoints[endpoint]['annotation']))
                ptprinthelper.ptprint("Bindings: ")
                for binding in tmp_endpoints[endpoint]['Bindings']:
                    ptprinthelper.ptprint("          %s" % binding)
                ptprinthelper.ptprint("")

            dce.disconnect()
            ptprinthelper.ptprint(f"Endpoints count: {len(tmp_endpoints)}")

            return tmp_endpoints

        except Exception as e:
            ptprinthelper.ptprint(f"[!] Chyba při enumeraci EPM: {e}")

        return tmp_endpoints
    

    def enumerate_mgmt(self) -> list[str]:

        dangerous_uuids = []
        other_uuids = []
        results =[]

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
                    results.append(tup[0].lower())
            
            return results

        except Exception as e:
            print(f"[!] Failed to connect/bind to MGMT interface: {e}")
            return []
        

    def try_authenticated_pipe_bind(self, pipe):
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

    def enumerate_open_known_pipes(self) -> list[str]:
        
        if self.pipes:
            known_pipes = self.pipes
        else:
            known_pipes = [
                'epmapper', 'browser', 'eventlog', 'lsarpc', 'samr', 'svcctl',
                'spoolss', 'netlogon', 'atsvc', 'wkssvc', 'ntsvcs', 'winreg', 'srvsvc'
            ]

        results = []

        for pipe in known_pipes:
            try:
               success = self.try_authenticated_pipe_bind(pipe)
               if success:
                   results.append(pipe)
            except Exception as e:
                print(f"[!] Chyba při enumeraci EPM: {e}")
                continue

        return results
    

    #Bruteforce - valid creds for specific pipe
    def rpc_pipe_dictionary_attack(self) -> list[Credential]:
        if not self.args.username_file and not self.args.username:
            print("[!] No username or username list provided.")
            return
        if not self.args.password_file and not self.args.password:
            print("[!] No password or password list provided.")
            return

        usernames = self._text_or_file(self.args.username, self.args.username_file)
        passwords = self._text_or_file(self.args.password, self.args.password_file)

        found = []

        for username in usernames:
            for password in passwords:

                print(f"[*] Trying {self.args.domain}\\{username}:{password}")

                try:
                    success = self.try_authenticated_pipe_bind(
                        host=self.args.ip,
                        username=username,
                        password=password,
                        pipe=self.args.pipe,
                        domain=self.args.domain
                    )
                    if success:
                        found.append(Credential(username=username, password=password))
                        print(f"[+] Found valid credentials: {self.args.domain}\\{username}:{password}")
                except Exception as e:
                    print(f"[-] Error with {self.args.domain}\\{username}:{password} - {str(e).strip()}")
                    continue

        return found
    
    def test_anonymous_smb_access(self):
        
        try:
            smb = SMBConnection(self.ip, self.ip, sess_port=self.port, timeout=5)
            smb.login('', '')  # (null session)

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