# ptapptest-plus

**ptapptest-plus** is a semi-automated penetration testing tool focused on application-layer protocols: **SNMP**, **DNS**, **LDAP**, and **MSRPC**.

- Modular and extensible architecture written in **Python**
- Integration with the **Penterep** testing platform (`ptlibs`)
- Designed for semi-automated penetration testing
- Supports testing of the following protocols:
  - **SNMP v1/v2/v3**: brute-force, version detection, write permission testing
  - **DNS**: zone transfer, reverse lookup, subdomain brute-force, DNSSEC/NSEC analysis
  - **LDAP**: anonymous bind, schema enumeration, directory search, user enumeration, brute-force, write access testing
  - **MSRPC**: endpoint mapper enumeration, pipe authentication, UUID listing, dictionary attacks

___

## How to Install
Follow these steps to set up and run the `ptapptestplus` tool in your local environment:

### 1. Download and Extract the Project

Download the ZIP archive and extract it to a folder.

### 2. Open Terminal and Create a Virtual Environment (Recommended)

- **Windows:**
```python -m venv venv```
```.\venv\Scripts\activate```

- **Linux:**
```python3 -m venv ven ```
```source venv/bin/activate```

You should now see `(venv)` in your terminal prompt.

### 5. Install the Tool

Navigate to the folder that contains `setup.py`
Install the tool using pip:
```pip install . ```

### 6. Run the Tool

Once installed, you can run the tool with:
``` ptapptestplus --help ```

___

## Example Usage

ptapptestplus snmp snmpv2-brute -ip <target ip> -cf <communities.txt>
ptapptestplus dns zone-transfer --domain <target domain>
ptapptestplus ldap bruteforce -ip <target ip> -ul <users.txt> -pl <passwords.txt> -bd <dc=example,dc=com>
ptapptestplus msrpc enumerate-epm -ip <target ip>   