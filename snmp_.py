import socket
from pyasn1.codec.ber import decoder
from pysnmp.proto import api
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from typing import List, NamedTuple
from pysnmp.proto.errind import RequestTimedOut
import argparse

from ptlibs import ptprinthelper

class Credential(NamedTuple):
    username: str
    password: str


class SNMPVersion(NamedTuple):
    v1: bool
    v2c: bool
    v3: bool


class AuthPrivProtocols(NamedTuple):
    auth_protocols: str
    priv_protocols: str

class SNMPResult(NamedTuple):
    version: SNMPVersion
    communities: list[str]


class SNMP:

    # Map protocol OIDs to human-readable names
    PROTOCOL_NAMES = {
        usmHMACMD5AuthProtocol: "usmHMACMD5AuthProtocol",
        usmHMACSHAAuthProtocol: "usmHMACSHAAuthProtocol",
        usmHMAC128SHA224AuthProtocol: "usmHMAC128SHA224AuthProtocol",
        usmHMAC192SHA256AuthProtocol: "usmHMAC192SHA256AuthProtocol",
        usmHMAC256SHA384AuthProtocol: "usmHMAC256SHA384AuthProtocol",
        usmHMAC384SHA512AuthProtocol: "usmHMAC384SHA512AuthProtocol",
        usmDESPrivProtocol: "usmDESPrivProtocol",
        usmAesCfb128Protocol: "usmAesCfb128Protocol",
        usmAesCfb192Protocol: "usmAesCfb192Protocol",
        usmAesCfb256Protocol: "usmAesCfb256Protocol",
        None: "None",
    }

    def __init__(self,
                 ip: str,
                 port: int,
                 output: bool = False,
                 single_community: str = None,
                 single_username: str = None,
                 single_password: str = None,
                 community_file: str = None,
                 username_file: str = None,
                 password_file: str = None,
                 valid_credentials_file: str = None,
                 spray: bool = False,
                 auth_protocols: str = None,
                 priv_protocols: str = None,
                 oid: str = "1.3.6",
                 oid_format: bool = False):

        self.ip = ip
        self.port = port

        self.output = output

        self.single_community = single_community
        self.single_username = single_username
        self.single_password = single_password

        self.community_file = community_file
        self.username_file = username_file
        self.password_file = password_file

        self.valid_credentials_file = valid_credentials_file

        self.spray = spray
        self.auth_protocols = auth_protocols
        self.priv_protocols = priv_protocols
        self.oid = oid
        self.oid_format = oid_format

    #def run(self):
        # self.banner()
        # asyncio.run(self.version_detection())
        # asyncio.run(self.user_enum())
        # asyncio.run(self.snmpv2_brute())
        # asyncio.run(self.snmpv3_brute())
        #
        # asyncio.run(self.test_snmpv2_write_permission())
        # asyncio.run(self.test_snmpv3_write_permissions())
        #
        # asyncio.run(self.getBulk_SNMPv2())
        # asyncio.run(self.getBulk_SNMPv3())

    def write_to_file(self, message_or_messages: str | list[str], filename: str):

        with open(filename, 'a') as f:
            if isinstance(message_or_messages, str):
                # If it's a single message, write it directly
                f.write(message_or_messages + '\n')
            elif isinstance(message_or_messages, list):
                # If it's a list of messages, iterate and write each one
                for message in message_or_messages:
                    f.write(message + '\n')

    def _text_or_file(self, text: str | None, file_path: str | None) -> List[str]:

        if text:
            return [text.strip()]
        elif file_path:
            try:
                with open(file_path, 'r') as file:
                    return [line.strip() for line in file if line.strip()]
            except Exception as e:
                ptprinthelper.ptprint(f"Error reading file {file_path}: {e}")
                return []
        else:
            ptprinthelper.ptprint("Error: Neither text nor file input provided.")
            return []

    # Function for getBulk SNMPv2/SNMPv3
    def format_timeticks(self, value):
        """
            Convert Timeticks to a human-readable string.
        """
        ticks = int(value)
        days, remainder = divmod(ticks, 8640000)  # 1 day = 8640000 timeticks
        hours, remainder = divmod(remainder, 360000)
        minutes, remainder = divmod(remainder, 6000)
        seconds = remainder // 100
        return f"{days} day, {hours}:{minutes:02}:{seconds:02}.{remainder % 100}"

    async def version_detection(self) -> SNMPVersion:
        """
           Detects the SNMP version supported by the target device.

           Parameters:
           - self.ip (str): The IP address of the target device.
           - self.port (int): The port number for SNMP communication.

           Returns:
           - SNMPVersion: An object containing three boolean attributes (`v1`, `v2c`, `v3`), each indicating
             whether the corresponding SNMP version is supported by the target device.
        """

        # Struct data
        v1: bool = False
        v2c: bool = False
        v3: bool = False

        ###########################################################################################
        # Detect v1                                                                               #
        ###########################################################################################
        iterator = await get_cmd(
            SnmpEngine(),
            CommunityData("public", mpModel=0),
            await UdpTransportTarget.create((self.ip, self.port)),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )

        errorIndication, errorStatus, errorIndex, varBinds = iterator

        if errorIndication:
            ptprinthelper.ptprint(errorIndication)

        elif errorStatus:
            ptprinthelper.ptprint(
                "{} at {}".format(
                    errorStatus.prettyptprinthelper.ptprint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                )
            )

        else:
            v1 = True
            for varBind in varBinds:
                ptprinthelper.ptprint("[+] Success!: ", end="")
                ptprinthelper.ptprint(" = ".join([x.prettyptprinthelper.ptprint() for x in varBind]))

        ###########################################################################################
        # Detect v2c                                                                              #
        ###########################################################################################
        iterator = await get_cmd(
            SnmpEngine(),
            CommunityData("public", mpModel=1),
            await UdpTransportTarget.create((self.ip, self.port)),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )

        errorIndication, errorStatus, errorIndex, varBinds = iterator

        if errorIndication:
            ptprinthelper.ptprint(errorIndication)

        elif errorStatus:
            ptprinthelper.ptprint("[-] Error!:")
            ptprinthelper.ptprint(
                "{} at {}".format(
                    errorStatus.prettyptprinthelper.ptprint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                )
            )

        else:
            v2c = True
            for varBind in varBinds:
                ptprinthelper.ptprint("[+] Success!: ", end="")
                ptprinthelper.ptprint(" = ".join([x.prettyptprinthelper.ptprint() for x in varBind]))

        ###########################################################################################
        # Detect v3                                                                               #
        ###########################################################################################
        iterator = await get_cmd(
            SnmpEngine(),
            UsmUserData("pentest"),
            await UdpTransportTarget.create((self.ip, self.port)),
            ContextData(),
        )

        errorIndication, errorStatus, errorIndex, varBinds = iterator

        if errorIndication:
            if isinstance(errorIndication, RequestTimedOut):
                ptprinthelper.ptprint(f"[-] Error!: {errorIndication}")
            else:
                ptprinthelper.ptprint(f"[+] Success!: {errorIndication}")
                v3 = True

        elif errorStatus:
            ptprinthelper.ptprint(
                "{} at {}".format(
                    errorStatus.prettyptprinthelper.ptprint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                )
            )

        else:
            v3 = True
            for varBind in varBinds:
                ptprinthelper.ptprint(" = ".join([x.prettyptprinthelper.ptprint() for x in varBind]))

        ptprinthelper.ptprint(SNMPVersion(v1, v2c, v3))
        return SNMPVersion(v1, v2c, v3)

    async def snmpv2_brute(self) -> List[str]:

        """
           Performs a dictionary attack on SNMPv2/1 to find valid communities.

           Parameters:
           - self.single_community (str): A single community string for SNMPv2/1 authentication.
           - self.community_file (str): Path to a file containing a list of communities for the dictionary attack.
           - self.ip (str): The IP address of the target device.
           - self.port (int): The port number for SNMP communication.
           - self.output (bool): If True, writes valid credentials to a file.

           Returns:
           - list[Credential]: A list of valid communities found during the attack.
           - None: If no credentials are found or required inputs are missing.
        """

        if not self.community_file and not self.single_community:
            ptprinthelper.ptprint("Error: Neither a community file nor a single community string was provided.")
            return []

        ptprinthelper.ptprint(f"\nStarting a dictionary attack on SNMPv2...")
        communities = self._text_or_file(self.single_community, self.community_file)
        valid_communities = []

        for community in communities:
            iterator = get_cmd(SnmpEngine(),
                               CommunityData(community),
                               await UdpTransportTarget.create((self.ip, self.port), timeout=0.1),
                               # Initialize transport target correctly
                               ContextData(),
                               ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)))
            errorIndication, errorStatus, errorIndex, varBinds = await iterator

            if not errorIndication and not errorStatus:
                ptprinthelper.ptprint(f"Valid community string found: {community}")
                valid_communities.append(community)
            else:
                ptprinthelper.ptprint(f"Error: {errorIndication or errorStatus} for {community}")

        if valid_communities:
            ptprinthelper.ptprint(f"\nValid communities: ")
            for community in valid_communities:
                ptprinthelper.ptprint(f"{community}")
            if self.output:
                for community in valid_communities:
                    self.write_to_file(community, "valid_communities.txt")

        else:
            ptprinthelper.ptprint("\nNo valid communities found :(")
        return valid_communities

    async def user_enum(self) -> list[str]:


        # Users from input
        users: list[str] = self._text_or_file(self.single_username, self.username_file)

        ptprinthelper.ptprint("\nStarting username enumeration...")
        valid_usernames = set()

        for username in users:
            try:
                iterator = get_cmd(
                    SnmpEngine(),
                    UsmUserData(username, "userenumeration", authProtocol=None, privProtocol=None),
                    await UdpTransportTarget.create((self.ip, self.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
                )
                errorIndication, errorStatus, errorIndex, varBinds = await iterator

                if not errorIndication and not errorStatus:
                    ptprinthelper.ptprint(f"Valid username found: {username}")
                    valid_usernames.add(username)
                elif "Wrong SNMP PDU digest" in str(errorIndication):
                    ptprinthelper.ptprint(f"Potential valid username: {username}")
                    valid_usernames.add(username)
                else:
                    ptprinthelper.ptprint(f"Error for username {username}: {errorIndication or errorStatus}")

            except Exception as e:
                ptprinthelper.ptprint(f"Error for username {username}: {e}")

        if valid_usernames:
            ptprinthelper.ptprint("\nPotential valid usernames:")
            for username in valid_usernames:
                ptprinthelper.ptprint(username)
                if self.output:
                    self.write_to_file(username, "potential_valid_usernames.txt")
        else:
            ptprinthelper.ptprint("No valid usernames found.")

        return list(valid_usernames)

    async def snmpv3_brute(self) -> list[Credential] | None:

        """
            Performs a dictionary attack on SNMPv3 to find valid credentials.

            Parameters:
            - self.single_username (str): A single username for SNMPv3 authentication.
            - self.single_password (str): A single password for SNMPv3 authentication.
            - self.username_file (str): Path to a file containing a list of usernames for the dictionary attack.
            - self.password_file (str): Path to a file containing a list of passwords for the dictionary attack.
            - self.auth_protocols (obj): The authentication protocol to use (e.g., usmHMACSHAAuthProtocol). Defaults to a set of standard protocols if not provided.
            - self.priv_protocols (obj): The encryption protocol to use (e.g., usmDESPrivProtocol). Defaults to a set of standard protocols if not provided.
            - self.spray (bool): Determines whether to try all passwords for each username (False) or all usernames for each password (True).
            - self.ip (str): The IP address of the target device.
            - self.port (int): The port number for SNMP communication.
            - self.output (bool): If True, writes valid credentials to a file.

            Returns:
            - list[Credential]: A list of valid credentials (username and password pairs) found during the attack.
            - None: If no credentials are found or required inputs are missing.
        """

        # Warning
        if not self.username_file and not self.single_username:
            ptprinthelper.ptprint("Error: Neither a username file nor a single username was provided.")
            return None

        # Warning
        if not self.password_file and not self.single_password:
            ptprinthelper.ptprint("Error: Neither a password file nor a single password was provided.")
            return None

        # Users and passwords from input
        users = self._text_or_file(self.single_username, self.username_file)
        passwords = self._text_or_file(self.single_password, self.password_file)
        valid_usernames = set()

        # setting the hash function for bruteforce
        default_auth_protocols = [
            usmHMACSHAAuthProtocol,
            usmHMACMD5AuthProtocol,
            usmHMAC128SHA224AuthProtocol,
            usmHMAC192SHA256AuthProtocol,
            usmHMAC256SHA384AuthProtocol,
            usmHMAC384SHA512AuthProtocol
        ]
        # setting the encryption function for bruteforce
        default_priv_protocols = [
            usmDESPrivProtocol,
            usmAesCfb128Protocol,
            usmAesCfb192Protocol,
            usmAesCfb256Protocol
        ]

        # If protocols are not set, perform username enumeration first
        if (self.auth_protocols is None or self.priv_protocols is None) and self.username_file:
            ptprinthelper.ptprint("\nNo auth or priv protocols set. Running username enumeration phase...")
            users = await self.user_enum()
            valid_usernames = set(users)
            if not users:
                ptprinthelper.ptprint("Sorry, it is not possible to find valid credentials with these usernames")
                return None

        auth_protocols = [self.auth_protocols] if self.auth_protocols else default_auth_protocols
        priv_protocols = [self.priv_protocols] if self.priv_protocols else default_priv_protocols

        protocols = [AuthPrivProtocols(a, p) for a in auth_protocols for p in priv_protocols]

        # Spray logic
        if self.spray:
            creds = [Credential(u, p) for p in passwords for u in users]
        else:
            creds = [Credential(u, p) for u in users for p in passwords]

        found_credentials = []  # store valid found credentials
        successful_protocol = None  # Track the successful protocol combination
        valid_usernames = set()

        # starting the attack
        ptprinthelper.ptprint(f"\nStarting a dictionary attack on SNMPv3...")

        for protocol in protocols:
            if successful_protocol:
                # If a valid protocol was found, skip other combinations
                if protocol != successful_protocol:
                    continue
            for cred in creds:
                try:
                    iterator = get_cmd(SnmpEngine(),
                                       UsmUserData(cred.username, cred.password, authProtocol=protocol.auth_protocols, privProtocol=protocol.priv_protocols),
                                       await UdpTransportTarget.create((self.ip, self.port)),
                                       ContextData(),
                                       ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)))
                    errorIndication, errorStatus, errorIndex, varBinds = await iterator

                    if not errorIndication and not errorStatus:
                        found_credentials.append(cred)
                        successful_protocol = protocol
                        valid_usernames.add(cred.username)
                        auth_name = self.PROTOCOL_NAMES.get(successful_protocol.auth_protocols, "Unknown Protocol")
                        priv_name = self.PROTOCOL_NAMES.get(successful_protocol.priv_protocols, "Unknown Protocol")
                        ptprinthelper.ptprint(f"Valid credentials found: Username: {cred.username}, Password: {cred.password}")
                        ptprinthelper.ptprint(f"Successful Authentication and Private protocols are: "
                              f"{auth_name} and {priv_name}")
                    elif "Wrong SNMP PDU digest" in str(errorIndication):
                        ptprinthelper.ptprint(f"Error: {errorIndication or errorStatus} for {cred.username}/{cred.password}")
                        valid_usernames.add(cred.username)
                    elif "Unknown USM user" in str(errorIndication):
                        ptprinthelper.ptprint(f"Error: {errorIndication or errorStatus} for {cred.username}/{cred.password}")
                    else:
                        ptprinthelper.ptprint(f"Error: {errorIndication or errorStatus} for {cred.username}/{cred.password}")

                except Exception as e:
                    ptprinthelper.ptprint(f"Error for {cred.username}/{cred.password}: {e}")

        if valid_usernames:
            ptprinthelper.ptprint("\nPotential valid usernames:")
            for username in valid_usernames:
                ptprinthelper.ptprint(username)

        if self.output and found_credentials:
            results = [f"Username: {cred.username}, Password: {cred.password}" for cred in found_credentials]
            self.write_to_file(results, f"{self.ip}_valid_credentials.txt")

        if found_credentials:
            ptprinthelper.ptprint("\nFound credentials:")
            for cred in found_credentials:
                ptprinthelper.ptprint(f"Username: {cred.username}, Password: {cred.password}")

        if successful_protocol:
            auth_name = self.PROTOCOL_NAMES.get(successful_protocol.auth_protocols, "Unknown Protocol")
            priv_name = self.PROTOCOL_NAMES.get(successful_protocol.priv_protocols, "Unknown Protocol")
            ptprinthelper.ptprint(f"\nSuccessful Authentication and Private protocols are: {auth_name} and {priv_name}")

        else:
            ptprinthelper.ptprint("\nNo valid credentials found :(")

        return found_credentials

    async def test_snmpv3_write_permissions(self):
        """
            Tests SNMPv3 write permissions by attempting to set a value on the target device.

            Parameters:
            - self.single_username (str): A single username for SNMPv3 authentication.
            - self.single_password (str): A single password for SNMPv3 authentication.
            - self.auth_protocols (obj): The authentication protocol (e.g., usmHMACSHAAuthProtocol). Defaults to usmHMACSHAAuthProtocol if not provided.
            - self.priv_protocols (obj): The encryption protocol (e.g., usmDESPrivProtocol). Defaults to usmDESPrivProtocol if not provided.
            - self.valid_credentials_file (str): Path to a file containing multiple valid credentials in the format `username: value, password: value`.
            - self.ip (str): The IP address of the target device.
            - self.port (int): The port number.

            Returns:
            - None: Prints the results of the write test, including success or failure messages.
        """

        default_auth_protocol = usmHMACSHAAuthProtocol
        default_priv_protocol = usmDESPrivProtocol

        if not self.auth_protocols:
            ptprinthelper.ptprint("\nBe aware that authentication protocol was not provided, so it is set as usmHMACSHAAuthProtocol")
            self.auth_protocols = default_auth_protocol

        if not self.priv_protocols:
            ptprinthelper.ptprint("\nBe aware that private protocol was not provided, so it is set as usmDESPrivProtocol")
            self.priv_protocols = default_priv_protocol

        creds = []

        Protocols = AuthPrivProtocols(self.auth_protocols, self.priv_protocols)

        if self.single_username and self.single_password:
            creds.append(Credential(self.single_username, self.single_password))
        elif self.valid_credentials_file:
            inputs = self._text_or_file(None, self.valid_credentials_file)
            for line in inputs:
                # Parse username and password directly from the line
                parts = line.split(", ")
                if len(parts) == 2:
                    # Extract username and password from parts
                    username = parts[0].split(": ")[1]
                    password = parts[1].split(": ")[1]
                    creds.append(Credential(username, password))
                else:
                    ptprinthelper.ptprint(f"Invalid format: {line}")
        else:
            ptprinthelper.ptprint("\nError: You must provide either a single username and password, or a file path with credentials.")
            return

        for cred in creds:
            try:
                ptprinthelper.ptprint(f"\nTesting write permission for User: {cred.username} with password: {cred.password}")
                iterator = set_cmd(
                    SnmpEngine(),
                    UsmUserData(cred.username, cred.password, authProtocol=Protocols.auth_protocols, privProtocol=Protocols.priv_protocols),
                    await UdpTransportTarget.create((self.ip, self.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0), OctetString("Hacked!"))
                )
                errorIndication, errorStatus, errorIndex, varBinds = await iterator

                if not errorIndication and not errorStatus:
                    ptprinthelper.ptprint("Write was successful!")
                    for varBind in varBinds:
                        ptprinthelper.ptprint(f"OID: {varBind[0]} was set to {varBind[1]}")
                else:
                    ptprinthelper.ptprint(f"Write failed: {errorIndication or errorStatus}")

            except Exception as e:
                ptprinthelper.ptprint(f"Error: {e}")

    async def test_snmpv2_write_permission(self):
        """
            Tests SNMPv2 write permissions by attempting to set a value on the target device.

            Parameters:
            - self.single_community (str): A single community string for SNMPv2/1 authentication.
            - self.community_file (str): Path to a file containing multiple valid community strings.
            - self.ip (str): The IP address of the target device.
            - self.port (int): The port number.

            Returns:
            - None: Prints the results of the write test, including success or failure messages.
        """

        if not self.community_file and not self.single_community:
            ptprinthelper.ptprint("Error: Neither a community file nor a single community string was provided.")
            return []

        communities = self._text_or_file(self.single_community, self.community_file)

        for community in communities:
            try:
                ptprinthelper.ptprint(f"\nTesting write permission for community string: {community}")
                iterator = set_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    await UdpTransportTarget.create((self.ip, self.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0), OctetString("Hacked!"))  # ToDo: instead of "Hacked!" put there original name to be less invasive
                )

                errorIndication, errorStatus, errorIndex, varBinds = await iterator

                if not errorIndication and not errorStatus:
                    ptprinthelper.ptprint("Write was successful!")
                    for varBind in varBinds:
                        ptprinthelper.ptprint(f"OID: {varBind[0]} was set to {varBind[1]}")
                else:
                    ptprinthelper.ptprint(f"Write failed: {errorIndication or errorStatus}")

            except Exception as e:
                ptprinthelper.ptprint(f"Error: {e}")

    async def getBulk_SNMPv2(self):

        """
           Executes an SNMPv2 bulk walk on the target device to retrieve MIB object values based on the specified OID.

           Parameters:
           - self.single_community (str): The community string for SNMPv2 authentication.
           - self.oid (str): The starting OID. Default is "1.3.6" if not provided.
           - self.oid_format (bool): Determines if the OID should be converted to a humanreadable format.
           - self.output (bool): Indicates whether the results should be saved to a file.
           - self.ip (str): The IP address of the target device.
           - self.port (int): The port number.

           Returns:
           - results (list): A list of formatted strings containing OID-value pairs retrieved from the target device.
       """

        if not self.community_file and not self.single_community:
            ptprinthelper.ptprint("\nNeither a community file nor a single community string was provided. Community is set as "
                  "default: public")
            self.single_community = "public"

        communities = self._text_or_file(self.single_community, self.community_file)

        ptprinthelper.ptprint("\nStarting SNMPv2 bulk walk...")
        results = []

        for community in communities:
            ptprinthelper.ptprint(f"Trying community: {community}")
            try:
                # Use walk_cmd to traverse the MIB
                objects = walk_cmd(
                    SnmpEngine(),
                    CommunityData(community),
                    await UdpTransportTarget.create((self.ip, self.port)),
                    ContextData(),
                    ObjectType(ObjectIdentity(self.oid))
                )

                # Iterate over the returned OID-value pairs
                async for errorIndication, errorStatus, errorIndex, varBinds in objects:
                    if errorIndication:
                        ptprinthelper.ptprint(f"Error: {errorIndication}")
                        break
                    elif errorStatus:
                        ptprinthelper.ptprint(f"Error: {errorStatus.prettyptprinthelper.ptprint()} at {errorIndex}")
                        break
                    else:
                        for oid, value in varBinds:
                            if self.oid_format:
                                oid = oid.prettyptprinthelper.ptprint()  # Convert OID to string
                            value_type = value.__class__.__name__.upper()  # Get the value type
                            value_str = value.prettyptprinthelper.ptprint()  # Convert value to string

                            # Format the value type and content
                            if value_type == "OCTET STRING":
                                value_output = f'STRING: "{value_str}"'
                            elif value_type == "OBJECT IDENTIFIER":
                                value_output = f'OID: {value}'
                            elif value_type == "TIMETICKS":
                                value_output = f'Timeticks: ({value_str}) {self.format_timeticks(value)}'
                            elif value_type == "INTEGER":
                                value_output = f'INTEGER: {value_str}'
                            else:
                                value_output = value_str  # Default for other types

                            # Construct the final formatted string
                            formatted_output = f"{oid} = {value_output}"
                            ptprinthelper.ptprint(formatted_output)
                            results.append(formatted_output)
                # Stop the loop if results are found
                if results:
                    ptprinthelper.ptprint(f"Results found with community '{community}', stopping further attempts.")
                    break

            except Exception as e:
                ptprinthelper.ptprint(f"Exception occurred for community '{community}': {e}")
                continue  # Move to the next community in case of errors
        if self.output:
            self.write_to_file(results, f"{self.ip}_snmpv2.txt")
        return results

    async def getBulk_SNMPv3(self):
        """
            Executes an SNMPv3 bulk walk on the target device to retrieve MIB object values based on the specified OID.

            Parameters:
            - self.single_username (str): The username for SNMPv3 authentication.
            - self.single_password (str): The password for SNMPv3 authentication.
            - self.auth_protocols (obj): The authentication protocol (e.g., usmHMACSHAAuthProtocol).
            - self.priv_protocols (obj): The encryption protocol (e.g., usmDESPrivProtocol).
            - self.oid (str): The starting OID. Default is "1.3.6" if not provided.
            - self.oid_format (bool): Determines if the OID should be converted to a humanreadable format.
            - self.output (bool): Indicates whether the results should be saved to a file.
            - self.ip (str): The IP address of the target device.
            - self.port (int): The port number.

            Returns:
            - results (list): A list of formatted strings containing OID-value pairs retrieved from the target device.
        """

        if not self.single_username:
            ptprinthelper.ptprint("\nUsername was not provided, Set the username to Start the snmpBUlk")
            return []

        if not self.single_password:
            ptprinthelper.ptprint("\nPassword was not provided, Set the password to Start the snmpBUlk")
            return []

        if not self.auth_protocols:
            ptprinthelper.ptprint("\nAuthentication protocol was not provided. Protocol is set as default: usmHMACSHAAuthProtocol")
            self.auth_protocol = usmHMACSHAAuthProtocol

        if not self.priv_protocols:
            ptprinthelper.ptprint("\nAuthentication protocol was not provided. Protocol is set as default: usmAesCfb128Protocol")
            self.priv_protocol = usmAesCfb128Protocol

        Protocols = AuthPrivProtocols(self.auth_protocols, self.priv_protocols)

        if self.oid is None:
            self.oid = "1.3.6"

        ptprinthelper.ptprint("\nStarting SNMPv3 bulk walk...")
        results = []

        objects = walk_cmd(
            SnmpEngine(),
            UsmUserData(self.single_username, self.single_password, authProtocol=Protocols.auth_protocols, privProtocol=Protocols.priv_protocols),
            await UdpTransportTarget.create((self.ip, self.port)),
            ContextData(),
            ObjectType(ObjectIdentity(self.oid))
        )

        # Iterate over the returned OID-value pairs
        async for errorIndication, errorStatus, errorIndex, varBinds in objects:
            if errorIndication:
                ptprinthelper.ptprint(f"Error: {errorIndication}")
                break
            elif errorStatus:
                ptprinthelper.ptprint(f"Error: {errorStatus.prettyptprinthelper.ptprint()} at {errorIndex}")
                break
            else:
                for oid, value in varBinds:
                    if self.oid_format:
                        oid = oid.prettyptprinthelper.ptprint()  # Convert OID to string
                    value_type = value.__class__.__name__.upper()  # Get the value type
                    value_str = value.prettyptprinthelper.ptprint()  # Convert value to string

                    # Format the value type and content
                    if value_type == "OCTET STRING":
                        value_output = f'STRING: "{value_str}"'
                    elif value_type == "OBJECT-IDENTIFIER":
                        value_output = f'OID: {value}'
                    elif value_type == "TIMETICKS":
                        value_output = f'Timeticks: ({value_str}) {self.format_timeticks(value)}'
                    elif value_type == "INTEGER":
                        value_output = f'INTEGER: {value_str}'
                    else:
                        value_output = value_str  # Default for other types

                    # Construct the final formatted string
                    formatted_output = f"{oid} = {value_output}"
                    ptprinthelper.ptprint(formatted_output)
                    results.append(formatted_output)

        if self.output:
            self.write_to_file(results, f"{self.ip}_snmpv3.txt")
        return results


    def banner(self):
        # ToDo: This is not complete and does not work
        try:

            # Initialize a socket and connect to the given IP and port
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)  # Set a 5-second timeout

            message = b"\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\0\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\0\x02\x01\0\x02\x01\0\x04\0\x04\0\x04\0\x30\x12\x04\0\x04\0\xa0\x0c\x02\x02\x37\xf0\x02\x01\0\x02\x01\0\x30\0"  # Placeholder message; adjust based on protocol expectations
            s.sendto(message, (self.ip, self.port))

            # Receive the banner and decode it to a string
            response, _ = s.recvfrom(1024)

            ptprinthelper.ptprint(response)
            ptprinthelper.ptprint(f"Raw Response (Hex): {response.hex()}")

            message_version = api.decodeMessageVersion(response)

            ptprinthelper.ptprint(f"Version: {message_version}")

            p_mod = api.PROTOCOL_MODULES[message_version]
            message, _ = decoder.decode(response, asn1Spec=p_mod.Message())
            ptprinthelper.ptprint(message.prettyptprinthelper.ptprint())

        except socket.error as e:
            ptprinthelper.ptprint(f"Error: {e}")
        finally:
            # Ensure the socket is closed after the operation
            s.close()

        pass


def main():


    parser = argparse.ArgumentParser(description="SNMP Penetration Testing Module")

    subparsers = parser.add_subparsers(dest="command", help="Select the functionality to execute")

    # Detection
    detection_parser = subparsers.add_parser("detection", help="Detect SNMP versions")
    detection_parser.add_argument("--ip", required=True, help="Target IP address")
    detection_parser.add_argument("--port", type=int, required=True, help="Target port")

    # SNMPv2 Brute Force
    snmpv2_brute_parser = subparsers.add_parser("snmpv2-brute", help="Perform SNMPv2 dictionary attack")
    snmpv2_brute_parser.add_argument("--ip", required=True, help="Target IP address")
    snmpv2_brute_parser.add_argument("--port", type=int, required=True, help="Target port")
    snmpv2_brute_parser.add_argument("--single-community", help="Single community string")
    snmpv2_brute_parser.add_argument("--community-file", help="File containing community strings")
    snmpv2_brute_parser.add_argument("--output", action="store_true", help="Save valid credentials to file")

    # SNMPv2 Write Permission
    snmpv2_write_parser = subparsers.add_parser("snmpv2-write", help="Test SNMPv2 write permissions")
    snmpv2_write_parser.add_argument("--ip", required=True, help="Target IP address")
    snmpv2_write_parser.add_argument("--port", type=int, required=True, help="Target port")
    snmpv2_write_parser.add_argument("--community-file", required=True, help="File containing community strings")

    # SNMPv2 Get Bulk
    snmpv2_getbulk_parser = subparsers.add_parser("snmpv2-walk", help="Listing of the MIB database for SNMPv2")
    snmpv2_getbulk_parser.add_argument("--ip", required=True, help="Target IP address")
    snmpv2_getbulk_parser.add_argument("--port", type=int, required=True, help="Target port")
    snmpv2_getbulk_parser.add_argument("--single-community", help="Single community string")
    snmpv2_getbulk_parser.add_argument("--community-file", help="File containing community strings")
    snmpv2_getbulk_parser.add_argument("--oid", default="1.3.6", help="OID to start from")
    snmpv2_getbulk_parser.add_argument("--oid-format", action="store_true", help="Use human readable OID format")
    snmpv2_getbulk_parser.add_argument("--output", action="store_true", help="Save results to file")

    # User Enumeration
    user_enum_parser = subparsers.add_parser("user-enum", help="Perform SNMPv3 user enumeration")
    user_enum_parser.add_argument("--ip", required=True, help="Target IP address")
    user_enum_parser.add_argument("--port", type=int, required=True, help="Target port")
    user_enum_parser.add_argument("--single-username", help="Single username")
    user_enum_parser.add_argument("--username-file", help="File containing usernames")
    user_enum_parser.add_argument("--output", action="store_true", help="Save valid users to file")

    # SNMPv3 Brute Force
    snmpv3_brute_parser = subparsers.add_parser("snmpv3-brute", help="Perform SNMPv3 dictionary attack")
    snmpv3_brute_parser.add_argument("--ip", required=True, help="Target IP address")
    snmpv3_brute_parser.add_argument("--port", type=int, required=True, help="Target port")
    snmpv3_brute_parser.add_argument("--single-username", help="Single username")
    snmpv3_brute_parser.add_argument("--username-file", help="File containing usernames")
    snmpv3_brute_parser.add_argument("--single-password", help="Single password")
    snmpv3_brute_parser.add_argument("--password-file", help="File containing passwords")
    snmpv3_brute_parser.add_argument("--auth-protocol", help="Authentication protocol")
    snmpv3_brute_parser.add_argument("--priv-protocol", help="Private protocol")
    snmpv3_brute_parser.add_argument("--output", action="store_true", help="Save valid credentials to file")
    snmpv3_brute_parser.add_argument("--spray", action="store_true", help="Enable spray mode")

    # SNMPv3 Get Bulk
    snmpv3_getbulk_parser = subparsers.add_parser("snmpv3-walk", help="Listing of the MIB database for SNMPv3")
    snmpv3_getbulk_parser.add_argument("--ip", required=True, help="Target IP address")
    snmpv3_getbulk_parser.add_argument("--port", type=int, required=True, help="Target port")
    snmpv3_getbulk_parser.add_argument("--single-username", help="Single username")
    snmpv3_getbulk_parser.add_argument("--single-password", help="Single password")
    snmpv3_getbulk_parser.add_argument("--valid-credentials-file", help="File containing valid credentials")
    snmpv3_getbulk_parser.add_argument("--auth-protocol", help="Authentication protocol")
    snmpv3_getbulk_parser.add_argument("--priv-protocol", help="Private protocol")
    snmpv3_getbulk_parser.add_argument("--oid", default="1.3.6", help="OID to start from")
    snmpv3_getbulk_parser.add_argument("--oid-format", action="store_true", help="Use human readable OID format")
    snmpv3_getbulk_parser.add_argument("--output", action="store_true", help="Save results to file")

    # SNMPv3 Write Permission
    snmpv3_write_parser = subparsers.add_parser("snmpv3-write", help="Test SNMPv3 write permissions")
    snmpv3_write_parser.add_argument("--ip", required=True, help="Target IP address")
    snmpv3_write_parser.add_argument("--port", type=int, required=True, help="Target port")
    snmpv3_write_parser.add_argument("--single-username", help="Single username")
    snmpv3_write_parser.add_argument("--single-password", help="Single password")
    snmpv3_write_parser.add_argument("--valid-credentials-file", help="File containing valid credentials")

    args = parser.parse_args()

    # Execute the corresponding function based on the selected command
    snmp_tool = SNMP(
        ip=args.ip,
        port=args.port,
        output=args.output if hasattr(args, 'output') else False,
        single_community=getattr(args, 'single_community', None),
        single_password=getattr(args, 'single_password', None),
        single_username=getattr(args, 'single_username', None),
        community_file=getattr(args, 'community_file', None),
        username_file=getattr(args, 'username_file', None),
        password_file=getattr(args, 'password_file', None),
        spray=getattr(args, 'spray', None),
        valid_credentials_file=getattr(args, 'valid_credentials_file', None),
        auth_protocols=getattr(args, 'auth_protocol', None),
        priv_protocols=getattr(args, 'priv_protocol', None),
        oid=getattr(args, 'oid', None),
        oid_format=getattr(args, 'oid_format', False))

    # Dispatch based on command
    if args.command == "detection":
        asyncio.run(snmp_tool.version_detection())
    elif args.command == "snmpv2-brute":
        asyncio.run(snmp_tool.snmpv2_brute())
    elif args.command == "snmpv2-write":
        asyncio.run(snmp_tool.test_snmpv2_write_permission())
    elif args.command == "snmpv2-walk":
        asyncio.run(snmp_tool.getBulk_SNMPv2())
    elif args.command == "user-enum":
        asyncio.run(snmp_tool.user_enum())
    elif args.command == "snmpv3-brute":
        asyncio.run(snmp_tool.snmpv3_brute())
    elif args.command == "snmpv3-walk":
        asyncio.run(snmp_tool.getBulk_SNMPv3())
    elif args.command == "snmpv3-write":
        asyncio.run(snmp_tool.test_snmpv3_write_permissions())
    else:
        ptprinthelper.ptprint("Invalid command. Use --help for available commands.")

if __name__ == '__main__':
    main()
