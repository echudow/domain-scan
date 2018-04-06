import logging
from typing import Tuple
from utils.scan_utils import ArgumentParser

###
# Testing scan function. Does nothing time consuming or destructive,
# but exercises many of the main hooks of domain-scan.


# Set a default number of workers for a particular scan type.
# Overridden by a --workers flag.
workers = 2


# Optional one-time initialization for all scans.
# If defined, any data returned will be passed to every scan instance and used
# to update the environment dict for that instance
# Will halt scan execution if it returns False or raises an exception.
#
# Run locally.
def init(environment: dict, options: dict) -> dict:
    logging.debug("Init function.")
    return {'constant': 12345}


# Optional one-time initialization per-scan. If defined, any data
# returned will be passed to the instance for that domain and used to update
# the environment dict for that particular domain.
#
# Run locally.
def init_domain(domain: str, environment: dict, options: dict) -> dict:
    logging.debug("Init function for %s." % domain)
    return {'variable': domain}


# Required scan function. This is the meat of the scanner, where things
# that use the network or are otherwise expensive would go.
#
# Runs locally or in the cloud (Lambda).
def scan(domain: str, environment: dict, options: dict) -> dict:
    logging.debug("Scan function called with options: %s" % options)

    # Perform the "task".
    complete = True
    logging.warn("Complete!")

    return {
        'complete': complete,
        'constant': environment.get('constant'),
        'variable': environment.get('variable')
    }


# Required CSV row conversion function. Usually one row, can be more.
#
# Run locally.
def to_rows(data):
    return [
        [data['complete'], data['constant'], data['variable']]
    ]


# CSV headers for each row of data. Referenced locally.
headers = ["Completed", "Constant", "Variable"]


# Optional handler for custom CLI parameters. Takes the args (as a list of
# strings) and returns a dict of the options values and names that the scanner
# expects, and a list of the arguments it didn't know how to parse.
#
# Should return a dict of the options parsed by this parser (not a mutated form
# of the opts that are passed to it) and a list of the remaining args that it
# didn't recognize.
def handle_scanner_args(args, opts) -> Tuple[dict, list]:
    parser = ArgumentParser(prefix_chars="--")
    parser.add_argument("--noop-delay", nargs=1)
    parsed, unknown = parser.parse_known_args(args)
    dicted = parsed.__dict__
    should_be_single = ["noop_delay"]
    for opt in dicted:
        if opt in should_be_single and dicted[opt] is not None:
            dicted[opt] = dicted[opt][0]
    dicted["noop_delay"] = int(dicted["noop_delay"], 10)
    return dicted, unknown
