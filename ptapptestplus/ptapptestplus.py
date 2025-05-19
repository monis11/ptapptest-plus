#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptapptest-plus - Application Server Penetration Testing Tool

    ptapptest-plus is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptapptest-plus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptapptest-plus.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse

from ptlibs import ptprinthelper, ptjsonlib


from ._version import __version__
from .modules.snmp import SNMP
from .modules._base import BaseArgs
from .modules.dns import DNS
from .modules.ldap import LDAP
#from .modules.msrpc import MSRPC

MODULES = {
    "snmp": SNMP,
    "dns": DNS,
    "ldap": LDAP,
    # "msrpc": MSRPC,
}


class PtAppTestplus:
    def __init__(self, args: BaseArgs) -> None:
        self.args = args

    def run(self) -> None:
        """Runs selected module with its configured arguments"""
        # Initialize JSON data
        ptjson = ptjsonlib.PtJsonLib()

        # Run the selected module
        module = MODULES[self.args.module](self.args, ptjson)
        module.run()
        module.output()


def parse_args() -> BaseArgs:
    """Processes command line arguments

    Returns:
        BaseArgs: parsed arguments of the selected module
    """
    parser = argparse.ArgumentParser(add_help=True)

    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}", help="print version"
    )
    parser.add_argument("-j", "--json", action="store_true", help="use Penterep JSON output format")
    parser.add_argument("--debug", action="store_true", help="enable debug messages")

    # Subparser for every application module
    subparsers = parser.add_subparsers(required=True, dest="module")
    for name, module in MODULES.items():
        module.module_args().add_subparser(name, subparsers)

    # First parse to get the module name, second parse to get the module-specific arguments
    args = parser.parse_args(namespace=BaseArgs)
    args = parser.parse_args(namespace=MODULES[args.module].module_args())

    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)

    return args


def main() -> None:
    global SCRIPTNAME
    SCRIPTNAME = "ptapptest-plus"
    args = parse_args()

    script = PtAppTestplus(args)
    script.run()


if __name__ == "__main__":
    main()
