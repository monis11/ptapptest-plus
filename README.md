# ptapptest-plus

**ptapptest-plus** is a semi-automated penetration testing tool focused on application-layer protocols: **SNMP**, **DNS**, **LDAP**, and **MSRPC**. It was developed as part of a master’s thesis and serves as a practical implementation of commonly used procedures in manual protocol testing.

- Modular and extensible architecture written in **Python**
- Integration with the **Penterep** testing platform (`ptlibs`)
- Designed for semi-automated penetration testing
- Supports testing of the following protocols:
  - **SNMP v1/v2/v3**: brute-force, version detection, write permission testing
  - **DNS**: zone transfer, reverse lookup, subdomain brute-force, DNSSEC/NSEC analysis
  - **LDAP**: anonymous bind, schema enumeration, directory search, user enumeration, brute-force, write access testing
  - **MSRPC**: endpoint mapper enumeration, pipe authentication, UUID listing, dictionary attacks

## Example Usage

ptapptestplus snmp snmpv2-brute -ip <target ip> -cf <communities.txt>
ptapptestplus dns zone-transfer --domain <target domain>
ptapptestplus ldap bruteforce -ip <target ip> -ul <users.txt> -pl <passwords.txt> -bd <dc=example,dc=com>
ptapptestplus msrpc enumerate-epm -ip <target ip>   