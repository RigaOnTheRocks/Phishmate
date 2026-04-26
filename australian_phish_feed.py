#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================
#   Phishmate
# - Enhanced context validation
# - Heuristic matching
# - Maintains whitelist-first approach
# - PERFORMANCE IMPROVEMENTS: Parallel fetching, caching, optimized regex
# - Python 3.7 compatible
# - Focuses on Australian entities
# ==============================================================

import os
import re
import csv
import sys
import time
import glob
import argparse
import signal
import zipfile
import pickle
import json
import multiprocessing
import yaml
from urllib.parse import urlparse
from io import StringIO, BytesIO
from datetime import datetime

import requests
import tldextract
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------
# Configuration
# ---------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load configuration from YAML file
with open(os.path.join(BASE_DIR, "config.yaml"), "r") as f:
    config = yaml.safe_load(f)

BRAND_FILE = os.path.join(BASE_DIR, config["brand_file"])
WHITELIST_FILE = os.path.join(BASE_DIR, config["whitelist_file"])
OUTPUT_DIR = os.path.join(BASE_DIR, config["output"]["output_dir"])
ARCHIVE_DIR = os.path.join(BASE_DIR, config["output"]["archive_dir"])
LOCAL_TLD_CACHE = os.path.join(BASE_DIR, config["cache"]["tld_cache_dir"])

# Cache for TLD extraction to avoid repeated processing
TLD_CACHE = {}

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)
os.makedirs(LOCAL_TLD_CACHE, exist_ok=True)
os.environ.setdefault("TLD_EXTRACT_CACHE", LOCAL_TLD_CACHE)
TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=LOCAL_TLD_CACHE)

# Debug: write a file with rejected hosts and the rule that rejected them
DEBUG_REJECTIONS = config["debug"]["debug_rejections"]
REJECTIONS_LOG = os.path.join(OUTPUT_DIR, config["output"]["rejection_log"])

# Checkpoint configuration
CHECKPOINT_DIR = os.path.join(BASE_DIR, config["debug"]["checkpoint_dir"])
os.makedirs(CHECKPOINT_DIR, exist_ok=True)
CHECKPOINT_FILE = os.path.join(CHECKPOINT_DIR, config["debug"]["checkpoint_file"])
PROGRESS_FILE = os.path.join(CHECKPOINT_DIR, config["debug"]["progress_file"])

# Thread pool for parallel fetching
MAX_WORKERS = config["workers"]["max_workers"]

# Process pool for CPU-bound classification tasks
MAX_PROCESS_WORKERS = config["workers"]["max_process_workers"]

# Global variable to track interruption
interrupted = False

# ---------------------------
# Load brand indicators & whitelist
# ---------------------------
try:
    with open(BRAND_FILE, encoding="utf-8") as f:
        indicators = json.load(f)
except FileNotFoundError:
    sys.exit(f"❌ Brand file not found: {BRAND_FILE}")

try:
    with open(WHITELIST_FILE, encoding="utf-8") as f:
        # normalize whitelist entries (lowercase, strip)
        OFFICIAL_WHITELIST = [d.strip().lower().rstrip('.') for d in json.load(f) if d and d.strip()]
except FileNotFoundError:
    OFFICIAL_WHITELIST = []

# ---------------------------
# Category tokens
# ---------------------------
NON_AUSTRALIAN_BANK_BRANDS = {"hsbc", "capitalone", "capital-one"}

def _filter_brands(values):
    return [v for v in (values or []) if v and v.lower() not in NON_AUSTRALIAN_BANK_BRANDS]

TELECOM_BRANDS   = _filter_brands(indicators.get("telecommunications"))
BANK_BRANDS      = _filter_brands(indicators.get("banks"))
UTIL_BRANDS      = _filter_brands(indicators.get("utilities"))
# Aviation brands are now merged into utilities
AVIATION_BRANDS  = _filter_brands(indicators.get("aviation"))
PHISHING_LURES   = indicators.get("phishing_lures", []) or []
MISC_LURES       = indicators.get("misc", []) or []
AUSTRALIAN_GEO   = indicators.get("australian_geo", []) or []

AUSTRALIAN_STATES = [
    "nsw", "vic", "qld", "wa", "sa", "tas", "act", "nt"
]

# Short state tokens that require extra Australian context to avoid false positives
# (sa matches Saudi Arabia, wa matches Washington, nt is common abbreviation, act is common English word)
AMBIGUOUS_STATE_TOKENS = {"sa", "wa", "nt", "act"}
UNAMBIGUOUS_STATE_TOKENS = {"nsw", "vic", "qld", "tas"}

# Prefixes that indicate generic phishing infrastructure (not Australian-targeted)
GENERIC_PHISHING_PREFIX_PATTERNS = [
    r"^account-\d+",  # account-12345, account-9876, etc
    r"^account\d+",   # account1234, account5678, etc
    r"^\d+-account",  # 123-account, 456-account, etc
    r"^secure-\d+",   # secure-123, etc
    r"^login-\d+",    # login-123, etc
    r"^verify-\d+",   # verify-123, etc
    r"^[a-f0-9]{32,}", # MD5/SHA hashes
    r"^bafybei",      # IPFS CIDv1
    r"^bafkre",       # IPFS CIDv1
]

GENERIC_PHISHING_PREFIXES = re.compile(
    r"|".join(GENERIC_PHISHING_PREFIX_PATTERNS), re.IGNORECASE
)

AUSTRALIAN_LONG_KEYWORDS = [
    "australia", "auspost", "post", "serviceaustralia", "gov.au", "ato", "abn", "mygov",
    "centrelink", "medicare", "ndis", "myagedcare", "health.gov.au", "sydney", "melbourne",
    "brisbane", "perth", "adelaide", "canberra", "goldcoast", "newcastle", "commbank",
    "commonwealth", "commonwealthbank",
    "westpac", "nab", "anz", "macquarie", "telstra", "optus", "tpg", "vodafone",
    "aussiebroadband", "originenergy", "agl", "energyaustralia"
]

AUSTRALIAN_FUZZY_PREFIX_CHARS = {"x", "z", "s"}

AUSTRALIAN_PREFIX_HINTS = {
    "app", "apps", "auth", "australia", "gov", "mygov", "my", "online",
    "portal", "service", "signin", "secure", "verify", "bank", "telecom",
    "energy", "power", "gas", "electricity", "account", "customer", "support",
    "help", "notification", "notice", "web", "mobile", "netbank", "internetbanking"
}

AUSTRALIAN_SUFFIX_HINTS = {
    "account", "accounts", "alert", "alerts", "apply", "application", "auth",
    "benefit", "benefits", "claim", "claims", "confirm", "confirmation",
    "connection", "delivery", "deposit", "deposits", "fund", "funds", "form",
    "forms", "job", "jobs", "login", "notice", "notices", "payment",
    "payments", "portal", "refund", "refunds", "secure",
    "service", "services", "support", "tax", "taxes", "update", "updates",
    "verify", "billing", "bills", "pay", "transfer", "transfers",
    "mail", "mailbox", "webmail", "email", "signin", "secure", "banking",
    "telecom", "broadband", "nbn", "mobile", "wireless", "energy",
    "electricity", "gas", "power", "customer", "help", "online"
}

STRICT_TELECOM_BOUNDARY = {"telstra", "optus", "tpg", "vodafone", "aussiebroadband"}

def signal_handler(signum, frame):
    """Handle interruption signals gracefully"""
    global interrupted
    print(f"\n⚠️  Received signal {signum}, saving progress before exiting...")
    interrupted = True

def save_checkpoint(processed_hosts, remaining_hosts, banking, government, utilities, rejected):
    """Save current processing state to checkpoint file"""
    try:
        checkpoint_data = {
            'processed_hosts': processed_hosts,
            'remaining_hosts': remaining_hosts,
            'banking': banking,
            'government': government,
            'utilities': utilities,
            'rejected': rejected,
            'timestamp': datetime.now().isoformat()
        }
        with open(CHECKPOINT_FILE, 'wb') as f:
            pickle.dump(checkpoint_data, f)
        
        # Also save human-readable progress
        with open(PROGRESS_FILE, 'w') as f:
            f.write(f"Processed: {len(processed_hosts)}\n")
            f.write(f"Remaining: {len(remaining_hosts)}\n")
            f.write(f"Banking: {len(banking)}\n")
            f.write(f"Government: {len(government)}\n")
            f.write(f"Utilities: {len(utilities)}\n")
            f.write(f"Rejected: {len(rejected)}\n")
            f.write(f"Timestamp: {checkpoint_data['timestamp']}\n")
        
        # Update progress in place to avoid cluttering the console
        # The carriage return (\r) moves the cursor to the start of the line
        # and the trailing space ensures any previous longer output is cleared.
        # Show processed and remaining hosts for better visibility
        remaining = len(remaining_hosts)
        print(f"\r💾 Progress saved to checkpoint. Processed {len(processed_hosts)}/{remaining} hosts so far.", end='', flush=True)
    except Exception as e:
        print(f"⚠️  Failed to save checkpoint: {e}")

def load_checkpoint():
    """Load processing state from checkpoint file if it exists"""
    try:
        if os.path.exists(CHECKPOINT_FILE):
            with open(CHECKPOINT_FILE, 'rb') as f:
                checkpoint_data = pickle.load(f)
            
            print(f"🔄 Resuming from checkpoint saved at {checkpoint_data['timestamp']}")
            return (
                checkpoint_data['processed_hosts'],
                checkpoint_data['remaining_hosts'],
                checkpoint_data['banking'],
                checkpoint_data['government'],
                checkpoint_data['utilities'],
                checkpoint_data['rejected']
            )
    except Exception as e:
        print(f"⚠️  Failed to load checkpoint: {e}")
    
    return None, None, set(), set(), set(), []

BRAND_HOSTING_TOKENS = [
    "cdn", "cloudfront", "ipfs", "w3s", "skynet", "siasky", "akamaized",
    "cloudflare", "fastly", "azureedge", "digitaloceanspaces"
]

CONSUMER_BRAND_EXCLUDES = {
    "spotify", "amazon", "facebook", "instagram", "netflix", "usps",
    "xfinity", "comcast", "fedex", "ups", "dhl", "apple", "icloud",
    "google", "youtube", "microsoft", "outlook", "paypal", "venmo",
    "ebay", "bestbuy", "metamask", "muitamask", "ntfx", "hsbc", "capitalone",
    "freemobile",
    "airbnb", "alrbnb"
}

PHISHING_ACTION_TOKENS = [
    "login", "secure", "account", "verify", "update", "alert", "notice",
    "refund", "billing", "invoice", "payment",
    "signin", "suspend", "transfer", "authenticate", "validation",
    "confirmation"
]

BANK_TOKENS_BOUNDARY = [
    "commbank", "cba", "commonwealth", "commonwealthbank", "westpac", "nab", "anz",
    "macquarie", "bendigobank", "bankofqueensland", "boq",
    "heritage", "ing", "mebank", "suncorp", "bankwest",
    "bankaustralia", "bankfirst", "beyondbank", "communityfirst",
    "creditunion", "defencebank", "firefighters", "goulburnmurray",
    "gsb", "horizonbank", "hume", "illawarra", "imbl",
    "newcastlepermanent", "pandc", "policebank", "qbank",
    "qtmb", "railways", "scu", "summerland", "teachersmutual",
    "thecapricornian", "unibank", "unitybank", "upbank", "voltage",
    "widebay", "wisr", "adelaidebank", "auswidebank", "ruralbank",
    "greaterbank", "pepper", "peppermoney", "mystatebank", "mystate"
]

TELECOM_TOKENS_BOUNDARY = [
    "telstra", "optus", "tpg", "vodafone", "aussiebroadband",
    "vocus", "macquarietelecom", "aldi", "amaysim",
    "belong", "circleslife", "dodo", "exetel", "felixmobile",
    "koganmobile", "lebara", "lycamobile", "moose", "spin",
    "woolworthsmobile", "yomo", "superloop", "launtel", "skymesh",
    "spintel", "catchconnect", "southernphone", "iinet", "iinetwest",
    "westnet", "aapt", "nextra", "canstar", "netspace", "activ8me",
    "fizznetworks", "greentel", "redbullmobile", "heliummobile",
    "ipstar", "skymuster", "bigblu"
]

UTIL_TOKENS_BOUNDARY = [
    "originenergy", "agl", "energyaustralia", "alintaenergy",
    "simplyenergy", "ergon", "ausgrid", "endeavourenergy",
    "essentialenergy", "jempower", "powercor", "citipower",
    "unitedenergy", "actewagl", "ewon", "sapower", "tasnetworks",
    "westernpower", "horizonpower", "synergy", "perthenergy",
    "powershop", "redenergy", "lumo", "clickenergy", "amber",
    "discoverenergy", "ovo", "dodoenergy", "commander", "globird",
    "sumopower", "energylo", "energex", "snowyhydro", "apagroup",
    "transgrid", "ausnet", "jemena", "electranet", "evoenergy",
    "momentumenergy", "engie", "winconnect",
    "powerdirect", "diamondenergy"
]

AVIATION_ACTION_TERMS = {
    "booking", "book", "flight", "flights", "trip", "mytrip", 
    "checkin", "check-in", "boarding", "seat", "baggage",
    "frequentflyer", "points", "status", "redemption", "redeem",
    "upgrade", "cancel", "refund", "change", "manage", "itinerary"
}

GOV_LURE_KEYWORDS = [
    "tax", "gst", "parcel", "delivery", "redelivery",
    "postoffice", "shipment", "tracking", "track",
    "reschedule", "refund", "ato", "revenue", "post",
    "payment",
    "benefit", "benefits", "subsidy", "relief",
    "support", "job", "jobs", "grant", "grants", "aid", "assistance",
    "claim", "claims"
]

# Australian strong government brands (also used as strict label markers)
STRONG_AUSTRALIAN_GOV = {
    "ato", "abn", "mygov", "centrelink", "medicare", "ndis", "myagedcare",
    "health.gov.au", "australia.gov.au", "serviceaustralia", "gov.au",
    "australia", "auspost", "post", "gov"
}

# Non-Australian entities that share tokens with Australian brands
NON_AUSTRALIAN_ENTITIES = {
    # Dutch banks (ABN AMRO)
    "abnamro", "abn-amro",
    # German telecom/utility
    "telekom", "deutsche-telekom",
    # European Vodafone
    "vodafonede", "vodafone-de", "vodafone-deutschland", "vodafone-cz", "vodafone-uk", "vodafone.es", "vodafone.it", "vodafone.pt", "vodafone.ro",
    # German/Swiss/US Aldi (not Australian)
    "aldi-sued", "aldi-nord", "aldi-de", "aldi-ch", "aldi-suisse", "aldi-us",
    # European ING bank
    "ing-de", "ing-nl", "ing-diba", "ing.de",
    # Other non-AU
    "ing-diba", "commerzbank", "deutsche-bank", "postbank",
    # UK government/revenue
    "hmrc", "hm-revenue", "hm-revenue-customs",
    # US government/tax
    "irs", "irs-gov",
    # US state/local revenue
    "phila", "ohio-revenue", "utah-gov",
    # Canadian revenue
    "canada-revenue", "cra-arc",
    # UK tax/DVLA
    "dvla", "gov-uk-tax", "hmrevenues",
    # Spanish/Portuguese ING
    "ing-es", "ing-pt",
    # Belgian/Dutch second-hand
    "2dehands", "2dehans",
    # French postal
    "laposte", "colissimo", "anpost",
    # Indian post
    "indiapost",
    # Emirates post
    "emiratespost",
    # Japanese post
    "japanpost", "japost",
    # Israeli post
    "israel-post", "israelpost",
    # Swiss post/finance
    "swisspost", "postfinance",
    # Non-Australian airlines
    "ryanair", "easyjet", "lufthansa", "airfrance", "klm", "british-airways",
    # Non-Australian energy companies
    "edf", "e-on", "rwe", "enel", "iberdrola",
    # Generic crypto/blockchain
    "metamask", "coinbase", "binance", "kraken", "trustwallet", "atomicwallet",
    # Generic tech companies (not Australian government)
    "adobe", "netflix", "spotify",
    # Additional non-Australian entities from user's list - BT (British Telecom)
    "bt", "btplc", "broadband", "broadbanduk", "broadbands", "broadbanduk", "broadband-bt", "btbroadband", "bt-broadband", "btinternet", "btconnect", "bthome", "btshop", "btmail", "btgroup", "btbusiness", "btenterprise", "btretail", "btglobal", "btworld", "btuk", "bt-uk", "btpublic", "btprivate", "btsecure", "btsecuremail", "btsecureweb", "btsecurelogin", "btsecureaccess", "btsecureportal", "btsecureaccount", "btsecureprofile", "btsecureidentity", "btsecureauth", "btsecureverify", "btsecureupdate", "btsecureconfirm", "btsecurevalidate", "btsecurecheck", "btsecurecontrol", "btsecuremanage", "btsecureadmin", "btsecurehelp", "btsecurecontact", "btsecureinfo", "btsecurenews", "btsecurealerts", "btsecurenotifications", "btsecuremessages", "btsecureinbox", "btsecureoutbox", "btsecurecompose", "btsecurereply", "btsecureforward", "btsecuredelete", "btsecuretrash", "btsecurespam", "btsecurejunk", "btsecurefolders", "btsecuresettings", "btsecurepreferences", "btsecureoptions", "btsecureconfig",
    # Additional non-Australian entities from user's list
    "1cde.zip-sneidjer", "2.remotesupport", "7-zip", "7e1b5cba.hsduecinfj", "amp-rewards", "amp.co.vu", "amp.tipsbladet", "app-hypenliguiid", "app-hyperliquild", "app-ing-servizi-2025", "app-ing.aviso-es", "assets-project-cloud.reconfirmation-zip", "bancogalicia.2banking", "bancogaliciahomebanking--galiciaar22", "bbva.hbbanking", "chrome-zip", "count-mail-163.com.petroraq", "frances.hbbanking", "gsb-oilless", "helping-trezor-help", "imtoken-bt", "ing-*", "jampel.edu", "lungtenzampamssresult.edu", "macquarie-france", "meta-support-accounting", "metaplay88a-amp", "metaplay88u-amp", "o365ecloudfile", "online-bt.bitbucket", "ourtime.*", "pubgm11117041.bc-zip", "pubgm11148815.bc-zip", "public7-zip", "riotinto-plc", "riotinto.cam", "riotinto.chiaplotscreator", "robux", "swapping-raydium-us", "tronenergy", "tronlink", "url.gsb.gov.zm", "whats-zip", "zip-archive.compressionlayer", "zip-lanjing", "zip-wanmeiworld", "zip-wps",
    # ABN AMRO related domains
    "abn-amanrosercure", "abn-bankcontact", "abn-bevestiggegevens", "abn-chost-list", "abn-deblokkeer", "abn-home-host", "abn-host-cpk", "abn-host-home", "abn-host-pkn", "abn-listing-host", "abn-login", "abn-passenaanvraag", "abn-telefoonbevestigen", "abn-verificatie", "abn-vervangend", "abn.app-kpx", "abn.tikkieverzoekje", "abn1.us", "abn2.me", "adx-abn", "m151abn", "m159abn", "nksa-abn",
    # Meta/Facebook/Instagram related
    "account-support-meta", "account.meta.com-support-id-3248", "ads-verify-manager-notify-support-center", "advert--support-verify-center", "meta.support-page-account-manage", "wallet-meta-support--cdn",
    # Crypto/Wallet related
    "auth-cdn-bitbuy-support-ca", "en-support-uphold-cdn-auth", "support--blockfi-cdn--auth", "support--sso--coinbasepros-cdn---oauth", "support-docs-trzorhardware-cdn", "support-en--ledgr-io-cdn-auth", "support-ledger-cdn--auth", "support-tzr-waltt-cdn", "uphold-wallet-cdn-support", "wallet-support-ledger-cdn",
    # UK/International Tax & Other
    "govuk-authtax", "govuk-taxservice", "taxserviceuk", "ukgov-taxservice", "hmcustoms.tax.secure-auth-details1", "internal-revenue-service", "moh-gov-sa", "member-neteller-com-wallet-account-support-login.malles",
    # General/Other
    "365auth-support", "account-gmail-support", "account-istore-support", "amzonsecurityservicesecuresupport", "ppuk-support-auth", "tax.securebankinggroup", "ymail-account"
}

# Non-Australian TLDs
NON_AUSTRALIAN_TLDS = {
    "cz", "de", "nl", "es", "it", "pt", "ro", "fr", "uk", "co.uk", "at", "ch", "be", "pl", "no", "us", "th", "cn", "ru", "jp", "kr", "in", "br", "ca", "mx"
}

# Government tokens boundary for classification
GOV_TOKENS_BOUNDARY = [
    "ato", "abn", "mygov", "centrelink", "medicare", "ndis", "myagedcare",
    "serviceaustralia", "auspost", "australiapost", "gov",
    "revenue", "taxation", "tax", "gst", "benefits", "support",
    "health.gov.au", "australia.gov.au", "human.services.gov.au",
    "scamwatch", "nasc", "agedcare", "workforceaustralia", "jobactive",
    "fairworkombudsman", "ombudsman", "humanrights", "esafety",
    "cybersecurity", "abf", "borderforce", "humanservices",
    "childsupport", "parentsnext", "costofliving", "energybillrelief"
]

def is_smart_non_australian_domain(host_lower, ext):
    """
    Smart detection of non-Australian domains based on multiple factors:
    1. Non-AU TLD presence anywhere in domain
    2. Country-specific patterns in subdomains
    3. Non-Australian entity patterns
    4. Suspicious hosting patterns
    """
    # Check for non-Australian TLDs anywhere in the domain (not just registered domain)
    for tld in NON_AUSTRALIAN_TLDS:
        if f'.{tld}.' in host_lower or host_lower.endswith(f'.{tld}'):
            return True, f"non_australian_tld:{tld}"
    
    # Check for country-specific patterns in subdomains (e.g., es., de., fr. before main domain)
    country_code_pattern = r'\.(es|de|nl|fr|it|pt|ro|ru|jp|kr|in|br|ca|mx|th|cn|be|pl|no|at|ch|co\.uk|uk)\.'
    import re
    if re.search(country_code_pattern, host_lower):
        return True, "country_specific_subdomain"
    
    # Check for non-Australian entities
    is_non_au, pattern_cat, pattern = has_non_australian_patterns(host_lower)
    if is_non_au:
        return True, f"non_australian_pattern:{pattern_cat}:{pattern}"
    
    # Check for suspicious hosting patterns that suggest non-AU origin
    suspicious_hosting = [
        'earthosting', 'swtest', 'codeanyapp', 'repl.co', 'github.io',
        'azurewebsites.net', 'firebaseapp', 'trycloudflare.com'
    ]
    for hosting in suspicious_hosting:
        if hosting in host_lower:
            # But only flag if it doesn't have clear Australian context
            has_au_context = (
                '.au' in host_lower or
                any(token in host_lower for token in ['australia', 'australian', 'commbank', 'nab', 'anz', 'westpac', 'telstra', 'optus', 'mygov', 'ato'])
            )
            if not has_au_context:
                return True, f"suspicious_hosting:{hosting}"
    
    return False, None

# ---------------------------
# Regex compilers & helpers
# ---------------------------
def _esc_join(tokens):
    toks = [t for t in tokens if t]
    return "|".join(map(re.escape, toks)) if toks else "(?!)"

# Pre-compile regex patterns with optimizations
BOUNDARY_BANKING = re.compile(rf"(?:^|[.\-])(?:{_esc_join(BANK_BRANDS)})(?:[.\-]|$)", re.IGNORECASE)
BOUNDARY_TELECOM = re.compile(rf"(?:^|[.\-])(?:{_esc_join(TELECOM_BRANDS)})(?:[.\-]|$)", re.IGNORECASE)
BOUNDARY_UTIL    = re.compile(rf"(?:^|[.\-])(?:{_esc_join(UTIL_BRANDS)})(?:[.\-]|$)", re.IGNORECASE)
BOUNDARY_AVIATION = re.compile(rf"(?:^|[.\-])(?:{_esc_join(AVIATION_BRANDS)})(?:[.\-]|$)", re.IGNORECASE)
BOUNDARY_LURE    = re.compile(rf"(?:^|[.\-])(?:{_esc_join(PHISHING_LURES + MISC_LURES)})(?:[.\-]|$)", re.IGNORECASE)

# Additional optimized patterns
AUSTRALIAN_CONTEXT_PATTERN = re.compile(
    rf"(?:^|[.\-_])(?:{'|'.join(map(re.escape, AUSTRALIAN_LONG_KEYWORDS))})(?:[.\-_]|$)",
    re.IGNORECASE
)
STATE_TOKEN_PATTERN = re.compile(
    rf"(?:^|[.\-_])(?:{'|'.join(map(re.escape, AUSTRALIAN_STATES))})(?:[.\-_]|$)",
    re.IGNORECASE
)

WEAK_BANKING = [
    "bank", "account", "secure", "verify", "alert",
    "update", "suspend", "notice", "signin", "security", "auth", "login",
    "netbank", "onlinebanking", "internetbanking", "mobilebanking", "ebanking",
    "digitalbanking"
]

BANKING_NOISE_TOKENS = {"netbank", "onlinebanking", "internetbanking", "mobilebanking", "ebanking", "digitalbanking"}

AUSTRALIAN_BANK_KEYWORDS = {
    "commbank", "cba", "commonwealth", "commonwealthbank", "westpac", "nab", "anz",
    "macquarie", "bendigobank", "bankofqueensland", "boq",
    "heritage", "ing", "mebank", "suncorp", "bankwest",
    "bankaustralia", "bankfirst", "beyondbank", "communityfirst",
    "creditunion", "defencebank", "firefighters", "goulburnmurray",
    "gsb", "horizonbank", "hume", "illawarra", "imbl",
    "newcastlepermanent", "pandc", "policebank", "qbank",
    "qtmb", "railways", "scu", "summerland", "teachersmutual",
    "thecapricornian", "unibank", "unitybank", "upbank", "voltage",
    "widebay", "wisr"
}

WEAK_TELECOM = [
    "telecom", "broadband", "nbn", "mobile", "wireless", "support", "secure", "verify",
    "service", "billing", "account", "customer", "online", "app", "myaccount"
]

BOUNDARY_WEAK = re.compile(
    rf"(^|[.\-])(?:{'|'.join([r'telstra', r'optus', r'tpg', r'vodafone', r'aussiebroadband', r'bank', r'post', r'gov'])})(?=[.\-]|$)",
    re.IGNORECASE
)

EXCLUDES = [
    # French banks
    "bnpparibas", "creditagricole", "societegenerale", "banquepostale", "lcl", "boursorama", "cic",
    # French telecom
    "orange", "free", "sfr", "swisscom",
    # French gov/health
    "cartevitale", "ameli", "hmrc", "hm-revenue-customs", "dvla", "irs", "irs-gov", "anpost", "colissimo", "laposte",
    # Payment platforms
    "paypal", "wise", "transferwise", "emiratesnbd",
    # Non-AU postal/courier
    "dhl", "dpd", "royalmail", "usps", "fedex", "bpost", "swisspost",
    "posteitaliane", "correos", "yodel", "evri", "gls", "ctt", "colisprive",
    "chronopost", "postnl", "diepost", "aramex", "postnord",
    "gouv.fr", "impots.gouv",
    # French savings banks
    "caisse-epargne", "caisse-depargne", "caisseepargne",
    # Swiss PostFinance
    "postfinance", "post-finance",
    # Indian Post
    "indiapost", "india-post",
    # Israeli Post
    "israel-post", "israelpost",
    # Emirates Post
    "emiratespost", "emirates-post",
    # Japanese Post
    "japanpost", "japost", "jppost",
    # Non-Australian banks
    "bankofamerica", "chase", "wellsfargo", "citibank",
    "desjardins", "caissepopulaire",
    # Crypto wallets (not Australian banks)
    "atomicwallet", "atomic-wallet", "trustwallet", "trust-wallet",
    # US state tax (Utah)
    "utah",
    # US city (Philadelphia)
    "phila",
    # UAE IT company (not Australian telecom)
    "commtel",
    # Telestream (video/streaming company, not Australian)
    "telestream",
    # Italian ING (anti-money laundering)
    "antiriciclaggio", "normativa-antiriciclaggio", "questionario-antiriciclaggio",
    # German classifieds
    "kleinanzeigen",
    # Dutch banks
    "knab",
    # AIB Ireland
    "aib-online", "aibsecure", "aib-auth",
    # UK Virgin Media (NOT Virgin Australia)
    "virgin-media", "virginmedia",
    # UK Regional Express (not Australian REX)
    "regionalexpress-uk",
    # Microsoft 365 / Office 365 (not Australian gov)
    "365online", "office365",
    # Crypto/web3 wallets
    "uphold-wallet", "wallet-meta", "wallet-support-ledger", "sol-incinerator",
    "support---ledgr", "support--blockfi", "support--sso--coinbase",
    "metamask", "mate-mask", "matemask", "mateimask",
    # Brazilian bank
    "animated-itau",
    # Canadian crypto
    "bitbuy",
    # UK O2 telecom
    "o2-update", "o2-billing",
    # Samsung phone scams
    "samsung-galaxy", "samsung-flip",
    # Indian ecommerce
    "flipkart",
    # Crypto gambling
    "bloxflip", "coin-flip", "chainflip",
    # Crypto DEX
    "dodoex-swap",
    # Free hosting providers
    "ultimatefreehost", "000webhostapp", "glitch.me", "netlify.app",
    "vercel.app", "firebaseapp", "web.app", "duckdns.org",
    "trycloudflare.com",
    # US Baltimore
    "baltimore",
    # Flip-related false positives
    "flip6", "flip7",
    # Non-Australian banks with "bnk" token (Thai, Korean, etc.)
    "kasikornbnk", "canbnk", "monbnk", "faresternbnk", "leadwesternbnk",
    "trustfinbnk", "capitalfiinbnk", "asianbnk", "inbnkl", "nbnde",
    "mnbnk-paribas", "mnnbnkvfy", "fgbnmvnbnk", "fhnbnvbuipr",
    "imzcxzygesnbn", "xeyrxxsinbn", "zgnbny", "commbnkkh",
    "openbnkonline", "acornbnk",
    # Non-Australian Vodafone (Germany, Spain, Italy, UK, Czech, Portugal, Romania)
    "vodafone-de", "vodafonede", "vodafone-deutschland", "vodafoneyanmda",
    "ref-myvodafone", "vodafoneidea", "vodafoneplay", "vodafonebusinessevents",
    "vodafonetelematics", "vodafone-customer-connect", "datenvodafone",
    # Non-Australian telecom - SaskTel (Canada)
    "sasktel",
    # Non-Australian telecom - Bimcell (Turkey)
    "bimcell",
    # Non-Australian BNPP Paribas (France)
    "mabanque-connexionbnpparibas",
    # BNL (Italian bank, not Australian)
    "cancelacionbnl", "cancelacironbnl",
    # Barclay's UK (not Australian)
    "barclayis",
    # Belong (international - not Australian telecom)
    "app-belong", "claim-belong",
    # Rhino (crypto/gaming, not Australian telecom Rhino Mobile)
    "rhino88", "goldrhino", "redrhino", "pink-rhino", "madrhino",
    "rhinocerotic", "congenialsumatranrhinoceros", "new-born-rhino",
    "rhino-ninja", "rhinoshield", "rhinocustomammo", "rhinofenence",
    "rhinogfx", "rhinonano", "rhinopowerelectric",
    "rhinopropertyservices", "rhinoservices", "rhinoscope",
    # "thefliptool" generic platform
    "thefliptool",
    # Generic "flip" crypto/gambling
    "flipgames",
    "flipmaster", "fliprex", "flipsidefind", "flipxcart",
    "bonidflipflops", "botoxlipflip", "bottleflipthegame",
    "capabflip", "cezarflip", "dzkflipa", "flavourflip",
    "flipcloud", "flipcre", "flipfield", "flipflopsandfros",
    "flipfloptravel", "flipghost", "flipimp", "flipkarticle",
    "flipknas", "flipp3fish", "flipp7byte", "flippbook",
    "flipperac", "flipperzero", "flippflopps", "flippmatic", "flippyy2coin",
    "flipvomix", "ghostflip", "mobilelegends", "mobilenetflip",
    "my-netflip", "solflipx", "ticketflip", "trymonflip",
    "tubeflippers", "tujuegoflip", "xflippbase", "zoneflip",
    # Crypto "swap" platforms (not Australian Dodo ISP)
    "dodo-swap",
    # Non-Australian DNB/Nor banks
    "dnbnor", "loginbncnratr", "loginbnnsonline",
    "logintrcnbnra", "privateloginbnnance", "verifactloginbnx",
    # Coin/Bitcoin related
    "bitcoinmiinetrix", "bitcoinbn", "coinbnnseprologinc",
    "coinextrainvests", "coinflipcom", "coinflipswap",
    "coinfliptrade", "coinflipx", "moneroflip",
    # Indonesian language patterns
    "lebaransabantalai", "grubwhatsaapterbaru", "eventgratispubgkhusus",
    # Brazilian domains
    "mundodosinconfidentes", "mundodosmoveisonline",
    # Portuguese "ktpgodigital"
    "ktpgodigital",
    # "nextrade" trading platform
    "nextrade", "talonextrader", "synextrade", "zernextrading",
    "dexanextrader", "ebinextrader",
    # "more" generic English word matches
    "more-grocery", "more-influence", "more-inv",
    "more-naked", "more-ng", "more-report", "more-sroon",
    "see--more", "see-more", "seeee-more", "score-for-more",
    "pipe-and-more", "zashop-more",
    # Luminacapital (non-Australian)
    "luminacapital",
    # "belong" generic (not Australian Belong telecom)
    "bigbluewhaleclub", "bigblueclubclud",
    # Amazingwhere (not Australian)
    "amazingwhere",
    # Dunkbpeach (not Australian)
    "dunkbpeach",
    # Wireplan (not Australian)
    "wireplan",
    # Rhinos (various unrelated businesses)
    "expertpstop.faceandrhinosymposium",
    "jetpre.faceandrhinosymposium",
    "shortblade.faceandrhinosymposium",
    # TPG spam tokens
    "tpgshd", "tpgys", "tpgaa", "rtpgacorzog",
    # Additional non-Australian entities from user's list
    "1cde.zip-sneidjer", "2.remotesupport", "7-zip", "7e1b5cba.hsduecinfj", "amp-rewards", "amp.co.vu", "amp.tipsbladet", "app-hypenliguiid", "app-hyperliquild", "app-ing-servizi-2025", "app-ing.aviso-es", "assets-project-cloud.reconfirmation-zip", "bancogalicia.2banking", "bancogaliciahomebanking--galiciaar22", "bbva.hbbanking", "chrome-zip", "count-mail-163.com.petroraq", "frances.hbbanking", "gsb-oilless", "helping-trezor-help", "imtoken-bt", "ing-*", "jampel.edu", "lungtenzampamssresult.edu", "macquarie-france", "meta-support-accounting", "metaplay88a-amp", "metaplay88u-amp", "o365ecloudfile", "online-bt.bitbucket", "ourtime.*", "pubgm11117041.bc-zip", "pubgm11148815.bc-zip", "public7-zip", "riotinto-plc", "riotinto.cam", "riotinto.chiaplotscreator", "robux", "swapping-raydium-us", "tronenergy", "tronlink", "url.gsb.gov.zm", "whats-zip", "zip-archive.compressionlayer", "zip-lanjing", "zip-wanmeiworld", "zip-wps",
    # ABN AMRO related domains
    "abn-amanrosercure", "abn-bankcontact", "abn-bevestiggegevens", "abn-chost-list", "abn-deblokkeer", "abn-home-host", "abn-host-cpk", "abn-host-home", "abn-host-pkn", "abn-listing-host", "abn-login", "abn-passenaanvraag", "abn-telefoonbevestigen", "abn-verificatie", "abn-vervangend", "abn.app-kpx", "abn.tikkieverzoekje", "abn1.us", "abn2.me", "adx-abn", "m151abn", "m159abn", "nksa-abn",
    # Meta/Facebook/Instagram related
    "account-support-meta", "account.meta.com-support-id-3248", "ads-verify-manager-notify-support-center", "advert--support-verify-center", "meta.support-page-account-manage", "wallet-meta-support--cdn",
    # Crypto/Wallet related
    "auth-cdn-bitbuy-support-ca", "en-support-uphold-cdn-auth", "support--blockfi-cdn--auth", "support--sso--coinbasepros-cdn---oauth", "support-docs-trzorhardware-cdn", "support-en--ledgr-io-cdn-auth", "support-ledger-cdn--auth", "support-tzr-waltt-cdn", "uphold-wallet-cdn-support", "wallet-support-ledger-cdn",
    # UK/International Tax & Other
    "govuk-authtax", "govuk-taxservice", "taxserviceuk", "ukgov-taxservice", "hmcustoms.tax.secure-auth-details1", "internal-revenue-service", "moh-gov-sa", "member-neteller-com-wallet-account-support-login.malles",
    # General/Other
    "365auth-support", "account-gmail-support", "account-istore-support", "amzonsecurityservicesecuresupport", "ppuk-support-auth", "tax.securebankinggroup", "ymail-account"
]

# Regex-only exclude patterns (NOT escaped by _esc_join — these are raw regex)
EXCLUDES_REGEX = [
    # Dutch/European ING Bank (dotted domains)
    r"ing\.nl", r"ing\.be", r"ing\.de", r"ing\.es", r"ing\.it", r"ing\.pt",
    # eBay (not Australian)
    r"ebay\.",
    # German banks (start of domain)
    r"^kleinanzeigen", r"^finanzinvest",
    # Dutch Knab bank
    r"^knab\.", r"\.knab\.",
    # Flip-related false positives (start/boundary)
    r"^flip", r"-flip",
    # Non-Australian Vodafone dotted patterns
    r"vodafone\.es", r"vodafone\.it", r"vodafone\.pt", r"vodafone\.ro",
    r"vodafone\.qpon", r"vodafone\.partner\.simo",
    # MyVodafone Spain
    r"myvodafone.*\.es",
    # Non-Australian telecom - Jio (India)
    r"^jio\.", r"(?<!\w)-jio\.",
    # AEON (Japanese, not Australian)
    r"^aeonbn", r"^aeonbnq",
    # Rhino dotted patterns
    r"rhino\.rest", r"rhino\.trade", r"rhinofl\.",
    # Glassflip sites
    r"glassflip\.com",
    # Flip dotted patterns
    r"cflipp\.", r"flipgames\.com", r"djs\.flipkart", r"flippers\.cc",
    r"li\.ctflip", r"stage\.flip",
    # More dotted patterns
    r"wolkenhimmel\.nutrition-n-more", r"zum\.nutrition-n-more",
    # TPG spam with spam TLDs
    r"tpgshd\.", r"tpgys\.", r"tpgaa\.",
    r"tpg[a-z]*\.buzz", r"tpg[a-z]*\.sbs", r"tpg[a-z]*\.xyz", r"tpg[a-z]*\.cfd",
    # Santander UK
    r"santander\.co\.uk", r"santander\.net",
    # Norwegian postal
    r"epost\.vic\.no",
    # Flip with dash patterns
    r"^flip-", r"flip-.*\.com$",
    # Flipscript/flipxy
    r"flipscript", r"flipxy\.com",
    # Flippr
    r"flippr",
    # Flipart
    r"flippant",
    # rhinoscope
    r"rhinoscope",
    # Generic bnk pattern (non-Australian bank naming)
    r"[a-z]{3,}bnk\.", r"bnk[a-z]{3,}\.",
    # Laposte.fr and colissimo.fr
    r"laposte\.fr", r"colissimo\.fr",
    # TPG with 4+ chars after
    r"tpg[a-z]{4,}\.",
    # Nutrition-n-more
    r"plain-tan-moose.*\.cpanel",
    # Mobile legends flip
    r"mobilelegends.*flip",
    # .zip TLD (not ZIP files - this is a real TLD often used for malware/crypto)
    r"\.zip$",
    # Cloudflare R2 storage (pub-*.r2.dev - hashes often contain brand-like strings)
    r"\.r2\.dev$",
    # ABN AMRO m15xabn pattern (Dutch bank, not Australian ABN)
    r"m15\d+abn",
    # Crypto AI trading "momentum" platforms
    r"immediate-momentum", r"momentum-ai", r"momentum-glow", r"momentum-sphere",
    r"momentum-x-capital", r"momentum\.airdrop", r"momentum\.beefy",
    r"momentum\.hub-", r"momentum\.portal", r"voltix-momentum",
    r"vortex-momentum", r"tge-momentum", r"bitcore-momentum",
    r"altex-momentum", r"register-momentum", r"sfc-dev\.ai-momentum",
    r"the-petro-momentum", r"theimmediate-momentum", r"the-momentum-x",
    r"claim-momentum", r"hub-momentum", r"momentum-technology",
    r"momentum-carta", r"momentum-airdrop",
    # Non-Australian amber (not Amber Energy AU)
    r"amber\.com\.ph", r"amber-kh\.", r"amber-sidonia", r"amber-taro",
    r"ipkobizness.*amber",
    # Non-Australian veolia (not Australian)
    r"veolia-northamerica", r"veolia\.cam", r"veolia\.com",
    # Generic "jump" (not Australian telecom)
    r"engine-jump", r"jump-press", r"jump\.0x1", r"naa-jump",
    # Generic "goodlife" (not Australian)
    r"goodlife-society", r"goodlife2024",
    # Generic "mate" (not Australian)
    r"trader-mate", r"y0-mate",
    # Generic "amp" (not AMP bank)
    r"amp\.cartermc", r"joyboy.*amp", r"tickets\.westgrove-amp",
]
BOUNDARY_EXCL = re.compile(rf"(?:{_esc_join(EXCLUDES)})", re.IGNORECASE)
BOUNDARY_EXCL_REGEX = re.compile(rf"(?:{'|'.join(EXCLUDES_REGEX)})", re.IGNORECASE)

# Additional non-Australian patterns for detection
NON_AU_PATTERNS = {
    # Dutch ING phrases
    "dutch_ing": [
        "mijn-ing", "betaalverzoek", "verificatie-ing", "2dehands", "2dehans",
        "bankverificatie", "betaling", "bevestiging", "veilig-online", "veiligbancontact",
        "overheid-fod", "fod-compensatie", "fod-dienst", "fod-overheid", "fohd-financien",
        "profiel-2dehands", "mijn-2dehands", "mijn-ing-betaalverzoekjes", "nuverifieren",
        "transactie-controle", "onlinebancontact", "online-veilig", "bancontact",
        "betaalwijze", "betaalverzoekjes",
    ],
    # Spanish ING phrases
    "spanish_ing": [
        "ing-es-", "app-seguros-ing", "cuentas-ing", "tarjetas", "inicio-app-cliente",
        "acceso-es", "es-accesospanel", "es-directclientes", "esalertas", "particular-es",
        "acceso-ing", "accesospanel", "directclientes",
    ],
    # German/Austrian ING phrases
    "german_ing": [
        "ing-jetzt", "ing-unterstutzung", "verifizieren", "girokonto", "jetzt-verifizieren",
        "unterstutzung", "online-verlangerung",
    ],
    # Belgian ING phrases (includes fod-* duplicates from Dutch — kept for categorization)
    "belgian_ing": [
        "be-ing", "belgie-ing", "ing-be-", "overdracht", "omgevinskeuze",
    ],
    # Italian ING phrases
    "italian_ing": [
        "verificazion-ing", "ing-it-logon", "postale",
    ],
    # Other ING patterns
    "other_ing": [
        "ing-loginturkey", "ing-hosgeldin", "ing-twyp", "ingdirct", "ingdirects",
        "ing-eshop", "ing-platform", "ing-tarjetas", "ing-terjeta",
        "ing-internetlogin", "ing-verificatie", "ing.fraedom", "ing.online-check",
        "ing.securecovid", "ing.talent-community", "ing.web-incidencia",
        "live-transaction-times-ing", "login-ing-be", "login-ing.com",
        "match-ing.cloud", "normativa-questionario-ing", "rec-loga-ing",
        "secure.portal-ing",
        "security-ing.com", "trust.wallet-web3", "www-telegram.ing",
        "aftershop.ing", "caisse-ing", "de-ing.", "elci-ing",
        "fashion-officers-difference-ing", "ing-app-nl", "ing-certifica",
        "ing-cuenta", "ing-direct.", "ing-dirt", "ing-homebankinfo",
        "ing-ledgeir", "ing-ledgerq", "ing-ledgert", "ing-logbanking",
        "ing-logincliente", "ing-mockup", "ing-moviles", "ing-onlines",
        "bancoonline-ing", "app-ing-es", "01notif-ing", "notif-ing-virification",
    ],
    # Dutch ABN patterns
    "dutch_abn": [
        "abn-klanten", "klanten-aanvraag", "klantenverificatie", "host-listing",
        "app-host-list", "co-host-listing", "app-list", "co-host-listing",
        "rent.abn-co",
    ],
    # Crypto/Blockchain (not banking)
    "crypto": [
        "atomic-wallet", "atomicwallet", "trustwallet", "trust-wallet",
        "wallet-web3", "wallet-webe", "kraken-log", "krakenlog", "change-now.ing", "changenow.ing",
        "imtoken.ing", "trczcr.ing", "trust.wallet-web3", "trust.wallet-webe", "wallet-web3.ing", "wallet-webe.ing",
    ],
    # Non-Australian postal
    "non_au_post": [
        "ae-emiratespost", "emiratespost", "indiapost", "israel-post",
        "jppost-", "postahnt", "post-ch.", "postfinance", "postelfinance",
        "swiss-federal", "delivery-post-office",
        "lnpost.secure", "notice-post.life", "post-notice.com",
        "poste-securelogin", "postlu-auth", "postoffice.redirect",
        "postofficen-ing",
    ],
    # Non-Australian banks
    "non_au_banks": [
        "america1creditunion", "bankofamerica", "tonabank", "creditunion-authority",
        "creditunion-banking", "creditunion-financial", "desjardins.creditunion",
        "desjardns.creditunion",
    ],
    # Generic non-Australian
    "generic_non_au": [
        "los-santos", "diamond-catch", "firefighters-vente", "he-cba.fit",
        "atom.eng-update", "support-atomic-cdn", "atomic--wallet", "atomicwallet",
    ],
    # Note: bnk banks, vodafone, flip, and non-AU telecom patterns are handled
    # by EXCLUDES/EXCLUDES_REGEX — not duplicated here to avoid redundancy.
}

NOISE_HOSTS = [
    "weebly","netlify","pages.dev","glitch","appspot","repl.co","herokuapp",
    "firebaseapp","web.app","vercel.app","azurewebsites.net","000webhostapp.com",
    "pantheonsite.io","godaddysites.com","wixsite.com","square.site","myfreesites.net",
    "github.io","glitch.me","trycloudflare.com","cprapid.com","duckdns.org","sytes.net",
    "ddns.net","codeanyapp.com","regruhosting.ru","blogspot.com","blogspot.ca","hubspotpagebuilder.net",
    "pointdns.cc","cloudfront.net","azureedge.net","webflow.io","mmspos.com","clik2pay.com",
    "usrfiles.com","eu.org","mjt.lu","nftstorage.link","pinata.cloud",
    "justns.ru","swtest.ru","tmweb.ru","selcdn.ru","tw1.ru","xsph.ru",
    "r2.dev"
]

# Pre-compiled regex for noise host suffix matching (e.g. *.vercel.app)
NOISE_HOST_SUFFIX_RE = re.compile(
    r"(?:^|[.])(" + "|".join(re.escape(n) for n in NOISE_HOSTS) + r")$",
    re.IGNORECASE,
)
# Hosting platforms where substring match is acceptable (the platform name
# rarely appears in a legitimate domain outside of being the hosting root)
NOISE_PLATFORM_SUBSTRINGS = frozenset({
    "weebly", "netlify", "glitch", "herokuapp", "github.io",
    "blogspot.com", "blogspot.ca", "r2.dev",
})

TELECOM_NOISE_BYPASS = {"telstra", "optus", "tpg", "vodafone", "aussiebroadband",
                        "iinet", "iinetwest", "westnet", "dodo", "belong",
                        "amaysim", "exetel", "lebara", "lycamobile", "woolworthsmobile",
                        "koganmobile", "felixmobile", "circleslife", "vocus",
                        "macquarietelecom", "nbn", "nbnco", "superloop", "skymesh"}
BANK_NOISE_BYPASS = {"commbank", "cba", "westpac", "nab", "anz", "macquarie",
                     "ing", "suncorp", "bankwest", "bendigobank", "bankofqueensland",
                     "boq", "mebank", "heritage", "bankaustralia", "scu",
                     "creditunion", "upbank", "volt"}

TELECOM_FUSED_BRANDS = {
    "telstra", "optus", "tpg", "vodafone", "aussiebroadband", "vocus", "macquarietelecom"
}

# Terms that indicate telecom/utility action/context (combined from both sets)
TELECOM_ACTION_TERMS = {
    "support", "help", "assistance", "login", "signin", "account", "accounts",
    "secure", "security", "verification", "verify", "auth", "authenticate",
    "payment", "payments", "pay", "refund", "billing", "bill", "invoice",
    "service", "services", "portal", "connect", "activation", "activate",
    "reset", "update", "notice", "client", "clients", "my", "online",
    "wireless", "mobility", "bills", "provider", "webmail", "myaccount",
    "broadband", "nbn", "mobile"
}

# Utility geo terms derived from Australian states + cities + country keywords
UTILITY_GEO_TERMS = set(AUSTRALIAN_STATES) | {
    "australia", "australian",
    "sydney", "melbourne", "brisbane", "perth", "adelaide",
    "canberra", "goldcoast", "newcastle"
}

UTILITY_ALLOWED_TLDS = {
    "au", "com", "net", "org", "biz", "co", "us", "online", "site", "top",
    "xyz", "icu", "app", "live", "support", "cc"
}

STRICT_TELECOM_BRANDS = {"telstra", "optus", "tpg", "vodafone", "aussiebroadband"}

# Brands that need extra Australian context to be classified as telecom
# (weaker brands + English words that accidentally match)
REQUIRES_TELECOM_CONTEXT = {
    # Secondary brands (not strict AU telecom)
    "vocus", "macquarietelecom", "aldi", "amaysim", "belong",
    "circleslife", "dodo", "exetel", "felixmobile", "koganmobile",
    "lebara", "lycamobile", "woolworthsmobile", "yomo",
    # English words that accidentally match — need explicit AU telecom context
    "material", "climate", "automated", "estimate",
    "amber", "lumo", "commander", "ovo",
    # Strict brands (included for the unified requires-context check)
    "telstra", "optus", "tpg", "vodafone", "aussiebroadband",
}

# ---------------------------
# Threat feeds
# ---------------------------
FEEDS = config["feeds"]

def normalize_domains(raw_values):
    """Extract and normalize domains from URLs"""
    cleaned = []
    for url in raw_values:
        if not url:
            continue
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ('http', 'https'):
                continue
            domain = parsed.netloc.split(':')[0]  # Remove port if present
            domain = domain.lower().strip("/")
            if domain and '.' in domain:  # Basic validation
                cleaned.append(domain)
        except Exception as e:
            print(f"Error parsing URL {url}: {str(e)}")
            continue
    # Deduplicate and sort domains
    cleaned = list(set(cleaned))
    cleaned.sort()
    return cleaned

def fetch_urlscan():
    """Fetch URLScan phishing feed and extract domains"""
    EXPORT_URL = "https://pro.urlscan.io/content/urlscan_phishing_url_feed_sample.json.zip"
    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Accept": "application/zip, application/json",
    }

    try:
        print("🌐 Downloading URLScan phishing feed...")
        response = session.get(EXPORT_URL, headers=headers)
        response.raise_for_status()

        # Extract JSON from ZIP
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            json_file = z.namelist()[0]  # Get first file in ZIP
            with z.open(json_file) as f:
                data = json.load(f)

        df = pd.DataFrame(data['results'] if isinstance(data, dict) and 'results' in data else data)
        print(f"🕵️ Found {len(df)} phishing URLs from URLScan")

        # Check for possible URL/domain columns
        url_column = None
        if 'url' in df.columns:
            url_column = 'url'
        elif 'domain' in df.columns:
            url_column = 'domain'
        elif 'page_url' in df.columns:
            url_column = 'page_url'

        if not url_column:
            print("⚠️ No URL or domain column found in URLScan data")
            return []

        raw_vals = df[url_column].dropna().astype(str).tolist()
        domains = normalize_domains(raw_vals)
        print(f"📊 Extracted {len(domains)} unique domains from URLScan")
        return domains

    except Exception as e:
        print(f"⚠️ Failed to fetch URLScan feed: {e}")
        return []
    finally:
        session.close()

def get_cached_tld_extraction(host: str):
    """Get TLD extraction result from cache or compute and cache it"""
    if host not in TLD_CACHE:
        TLD_CACHE[host] = TLD_EXTRACTOR(host)
    return TLD_CACHE[host]

def _normalize_brand_label(label):
    return re.sub(r'[^a-z0-9]', '', label.lower())

def is_noise_host(h):
    """Check if a host is on a known free/hosting platform."""
    # Fast suffix check via pre-compiled regex
    if NOISE_HOST_SUFFIX_RE.search(h):
        return True
    # For specific platforms, substring match is also a strong signal
    if any(p in h for p in NOISE_PLATFORM_SUBSTRINGS):
        return True
    return False

def has_non_australian_entity(host_lower):
    """Check if domain contains known non-Australian entity patterns or non-AU TLD"""
    # Check for known non-Australian entity patterns
    for entity in NON_AUSTRALIAN_ENTITIES:
        if entity in host_lower:
            return True
    # Check for non-Australian TLDs anywhere in the domain (not just registered domain)
    # This catches cases like "something.de-bestaetigungonline.com"
    for tld in NON_AUSTRALIAN_TLDS:
        if f'.{tld}.' in host_lower or host_lower.endswith(f'.{tld}'):
            return True
    return False

def has_non_australian_patterns(host_lower):
    """Check if domain matches any non-Australian phishing patterns from NON_AU_PATTERNS"""
    for category, patterns in NON_AU_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in host_lower:
                return True, category, pattern
    return False, None, None

# ---------------------------
# Helper functions for parallel fetching
# ---------------------------
FEED_FALLBACKS = config["feed_fallbacks"]
_FEED_HEADERS = config["feed_headers"]


def _parse_feed_response(text, url):
    """Parse CSV or plain-text feed response into a list of lines."""
    if url.endswith(".csv"):
        reader = csv.reader(StringIO(text))
        rows = list(reader)
        if rows and "url" in rows[0]:
            return [row.get("url", "").strip() for row in csv.DictReader(StringIO(text)) if row.get("url")]
        return [row[0].strip() for row in rows if row]
    return text.splitlines()


def _try_url(url, attempts, sleep_seconds, headers):
    """Try to fetch a URL with retries. Returns parsed data or None."""
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            r = requests.get(url, headers=headers, timeout=60)
            if r.status_code != 200:
                raise requests.HTTPError(f"HTTP {r.status_code}", response=r)
            return _parse_feed_response(r.text, url), None
        except Exception as e:
            last_error = e
            print(f"⚠️ Attempt {attempt}/{attempts} failed for {url}: {e}")
            if attempt < attempts:
                time.sleep(sleep_seconds)
    return None, last_error


def fetch_feed(url: str, attempts: int = 3, sleep_seconds: int = 3):
    headers = _FEED_HEADERS
    fallback_url = FEED_FALLBACKS.get(url)

    # Build ordered list of URLs to try
    candidates = [url]
    if fallback_url:
        candidates.append(fallback_url)

    for candidate in candidates:
        if candidate != url and fallback_url:
            print(f"🔄 {url} failed, trying fallback: {fallback_url}")
        data, error = _try_url(candidate, attempts, sleep_seconds, headers)
        if data is not None:
            return data

    # All candidates failed
    print(f"❌ Failed to fetch {url} after {attempts} attempts per URL")
    return []

def fetch_all_feeds_parallel():
    """Fetch all feeds in parallel for better performance"""
    print(f"🚀 Fetching {len(FEEDS)} feeds in parallel with {MAX_WORKERS} workers...")
    all_entries = []
    feed_counts = {}
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all fetch tasks
        future_to_url = {executor.submit(fetch_feed, url): url for url in FEEDS}
        
        # Collect results as they complete
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                entries = future.result()
                all_entries.extend(entries)
                feed_counts[url] = len(entries)
                print(f"📥 {url} -> {len(entries)} entries")
            except Exception as e:
                print(f"⚠️ Error fetching {url}: {e}")
                feed_counts[url] = 0
    
    return all_entries, feed_counts

def normalize_host(entry):
    s = entry.strip().lower()
    s = s.replace("[.]", ".").replace("hxxp", "http")
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    if s.startswith("www."): s = s[4:]
    return s.rstrip(".")

def is_valid_host(h):
    return bool(re.search(r"[a-z0-9\-]+\.[a-z]{2,}", h))

def _has_token(host, token):
    if re.search(rf"(^|[.\-]){re.escape(token)}(?=[.\-]|$)", host, re.IGNORECASE):
        return True

    host_lower = host.lower()
    token_lower = token.lower()
    idx = host_lower.find(token_lower)
    if idx == -1:
        return False

    # Skip substring fallback for very short tokens (< 3 chars) to avoid
    # excessive false positives (e.g., "au" in "saudi", "in" in "login")
    # But allow 3-char tokens like "ato", "abn", "nbn", "anz", "nab" through
    if len(token_lower) < 3:
        return False

    before = host_lower[:idx]
    after = host_lower[idx + len(token_lower):]

    def _prefix_ok():
        if not before:
            return True
        if not before[-1].isalpha():
            return True
        if any(before.endswith(hint) for hint in AUSTRALIAN_PREFIX_HINTS):
            return True
        if before[-1] in AUSTRALIAN_FUZZY_PREFIX_CHARS:
            trimmed = before[:-1]
            if any(trimmed.endswith(hint) for hint in AUSTRALIAN_PREFIX_HINTS):
                return True
        return False

    def _suffix_ok():
        if not after:
            return True
        if not after[0].isalpha():
            return True
        for hint in AUSTRALIAN_SUFFIX_HINTS:
            if after.startswith(hint):
                return True
        return False

    return _prefix_ok() and _suffix_ok()

def _normalize_for_matching(s):
    s = s.lower()
    s = s.replace("lnfo", "info").replace("p0st", "post").replace("lnterac", "interac")
    return s.translate(str.maketrans({'0': 'o','3': 'e','4': 'a'}))

def has_australian_context(host, ext, rd=None):
    rd = rd or (f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain)
    suffix = (ext.suffix or "").lower()
    if suffix == "au" or suffix.endswith(".au"):
        return True

    suffix_labels = [s for s in (ext.suffix or "").lower().split('.') if s]

    host_lower = host.lower()
    rd_lower = rd.lower()

    # More inclusive Australian context detection
    # Check for any Australian brand in the host (even if not perfect match)
    for brand in BANK_BRANDS + TELECOM_BRANDS + UTIL_BRANDS + AVIATION_BRANDS:
        if brand in host_lower or brand in rd_lower:
            return True
    
    # Check for common Australian keywords with more flexible matching
    australian_indicators = {
        'australia', 'australian', 'aus', 'au', 'gov.au', 'ato', 'abn', 'mygov',
        'centrelink', 'medicare', 'ndis', 'myagedcare', 'health.gov.au', 'serviceaustralia',
        'auspost', 'australiapost', 'tax', 'revenue', 'parcel', 'delivery', 'redelivery'
    }
    
    if any(indicator in host_lower or indicator in rd_lower for indicator in australian_indicators):
        return True
    
    # Check for state abbreviations (more inclusive)
    state_abbreviations = {"nsw", "vic", "qld", "wa", "sa", "tas", "act", "nt"}
    if any(state in host_lower or state in rd_lower for state in state_abbreviations):
        return True
    
    # Check for common phishing patterns that target Australian entities
    phishing_patterns = [
        r'login\-', r'secure\-', r'account\-', r'verify\-', r'update\-', r'alert\-',
        r'notice\-', r'refund\-', r'billing\-', r'invoice\-', r'payment\-',
        r'signin\-', r'suspend\-', r'transfer\-', r'authenticate\-', r'validation\-',
        r'\-login', r'\-secure', r'\-account', r'\-verify', r'\-update'
    ]
    
    if any(re.search(pattern, host_lower, re.IGNORECASE) for pattern in phishing_patterns):
        # If we have phishing patterns, be more inclusive with Australian context
        simple_au_indicators = {'au', 'aus', 'australia'}
        if any(indicator in host_lower or indicator in rd_lower for indicator in simple_au_indicators):
            return True
    
    # Check for 'au' in various forms
    if re.search(r'(?:^|[^a-z0-9])au(?:[^a-z0-9]|$)', host_lower, re.IGNORECASE):
        return True
    
    # Check for common typos and variations
    typo_patterns = [
        r'austrailia', r'austrailiapending', r'australiaqov', r'australiaqov',
        r'commbank', r'commonwealth', r'telstra', r'optus', r'vodafone'
    ]
    
    if any(re.search(pattern, host_lower, re.IGNORECASE) for pattern in typo_patterns):
        return True
    
    return False



def is_whitelisted(host, rd):
    # OFFICIAL_WHITELIST entries are normalized lower-case on load.
    for w in OFFICIAL_WHITELIST:
        if not w:
            continue
        # exact host or exact root domain match
        if host == w or rd == w:
            return True
        # host is a subdomain of a whitelisted root (e.g. track.canadapost.ca -> canadapost.ca)
        if host.endswith("." + w):
            return True
        # whitelist entry might be a subdomain itself (explicit)
        if w.endswith("." + rd):
            if host == w or host.endswith("." + w) or host.endswith(w):
                return True
        # handle entries that are composite lookalikes the user added:
        # if whitelist entry equals the registered domain rd, catch it (already covered),
        # but also allow the whitelist to include the exact registered domain of lookalikes.
        if w == rd:
            return True
    return False



# ---------------------------
# Tracking subdomain prefixes we want to drop even under legit roots
# ---------------------------
REJECT_PREFIXES = (
    "stats.", "sslstats.", "smetrics.", "smetric.", "s-analytics.", "omtrdc.", "s7.", "trk.", "trk2.",
    "strack.", "strck.", "sstat.", "sentry.", "track.", "tracking."
)

REJECT_SUBDOMAIN_KEYWORDS = ("stats", "sslstats", "smetrics", "smetric", "s-analytics", "omtrdc", "strack", "sstat", "sentry")

# ---------------------------
# Classification (whitelist-first, more aggressive)
# ---------------------------
def classify_host(host: str):
    ext = get_cached_tld_extraction(host)  # Use cached TLD extraction
    rd = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    host_norm = _normalize_for_matching(host)
    rd_norm = _normalize_for_matching(rd)

    host_lower = host_norm
    rd_lower = rd_norm
    suffix_lower = (ext.suffix or "").lower()

    # Check for Australian TLDs
    australian_tlds = {"au", "com.au", "net.au", "org.au"}
    has_au_suffix = suffix_lower in australian_tlds or any(suffix_lower.endswith(f".{tld}") for tld in australian_tlds)

    util_brand_raw = False
    util_brand_confident = False

    def has_australian_state_token(value):
        if any(_has_token(value, tok) for tok in UNAMBIGUOUS_STATE_TOKENS):
            return True
        # Ambiguous state tokens need extra Australian signal
        for tok in AMBIGUOUS_STATE_TOKENS:
            if _has_token(value, tok):
                has_extra = (
                    any(_has_token(value, k) for k in STRONG_AUSTRALIAN_GOV) or
                    any(_has_token(value, k) for k in AUSTRALIAN_LONG_KEYWORDS if len(k) >= 6)
                )
                if has_extra:
                    return True
        labels = re.split(r'[.-]', value)
        return any(label in UNAMBIGUOUS_STATE_TOKENS for label in labels)

    def contains_keyword(tokens):
        return any(_has_token(host_norm, tok) for tok in tokens) or any(_has_token(rd_norm, tok) for tok in tokens)

    def has_bank_keyword():
        return contains_keyword(BANK_TOKENS_BOUNDARY)

    telecom_brand_tokens = [tok.lower() for tok in TELECOM_BRANDS if tok]
    # STRICT_TELECOM_BRANDS is defined at module level (line 820)

    def _boundary_match(value, token):
        pattern = rf"(^|[.\-_]){re.escape(token)}(?=[.\-_]|$)"
        return re.search(pattern, value, re.IGNORECASE) is not None

    def has_utility_action():
        return any(term in host_lower for term in TELECOM_ACTION_TERMS)

    def has_telecom_brand():
        nonlocal util_brand_raw, util_brand_confident

        # NOTE: spin/bnb/boost rejection is handled at classify_host level (before weak matching)
        # Do NOT duplicate here to avoid inconsistent brand lists

        # EARLY REJECTION: Reject "dodo" when it's crypto DEX (not Australian ISP Dodo)
        if 'dodo' in host_lower:
            is_crypto_dex = any(
                term in host_lower
                for term in ['dodoex', 'dodo-ex', 'swap', 'dex', 'defi', 'liquidity', 'pool']
            )
            has_aus_telco_context = any(
                brand in host_lower
                for brand in ['telstra', 'optus', 'tpg', 'vodafone', 'iinet', 'webmail', 'broadband', 'nbn']
            )
            if is_crypto_dex and not has_aus_telco_context:
                return False

        # EARLY REJECTION: Reject non-Australian telecom brands without Australian context
        # Lebara - international MVNO (Europe, Middle East, Asia)
        if 'lebara' in host_lower or 'lycamobile' in host_lower:
            has_aus_context = (
                '.au' in host_lower or
                any(term in host_lower for term in ['telstra', 'optus', 'tpg', 'aussiebroadband', 'iinet', 'webmail']) or
                any(term in host_lower for term in AUSTRALIAN_STATES)
            )
            if not has_aus_context:
                return False

        # EARLY REJECTION: Reject Aldi unless it is clearly an Australian mobile service.
        if 'aldi' in host_lower:
            # Accept only if the host ends with .au or contains the word "mobile"
            is_au_mobile = (
                '.au' in host_lower or
                'mobile' in host_lower
            )
            # Exclude known non‑Australian Aldi domains
            non_au_aldi = any(term in host_lower for term in ['aldi-sued', 'aldi-nord', 'aldi-de', 'aldi-ch', 'aldi-suisse', 'aldi-us'])
            if non_au_aldi or not is_au_mobile:
                return False

        # EARLY REJECTION: Reject Canadian bank Tangerine
        if 'tangerine' in host_lower:
            has_aus_context = (
                '.au' in host_lower or
                any(term in host_lower for term in ['telstra', 'optus', 'tpg', 'vodafone', 'aussiebroadband', 'webmail']) or
                any(term in host_lower for term in AUSTRALIAN_STATES)
            )
            if not has_aus_context:
                return False

        # EARLY REJECTION: Reject NBN when paired with non-AU bank signals (Thai/Korean banks)
        if 'nbn' in host_lower:
            has_non_au_bank_signal = any(
                term in host_lower
                for term in ['bnk', 'kasikorn', 'canbnk', 'monbnk', 'farestern', 'leadwestern', 'trustfin', 'capitalfiin']
            )
            if has_non_au_bank_signal:
                return False

        # EARLY REJECTION: Reject moose without explicit telco brand (common word, crypto projects)
        if 'moose' in host_lower:
            has_explicit_telco = any(
                brand in host_lower
                for brand in ['telstra', 'optus', 'tpg', 'vodafone', 'aussiebroadband', 'iinet']
            )
            if not has_explicit_telco:
                return False

        # EARLY REJECTION: Reject yomo without explicit telco context (common word)
        if 'yomo' in host_lower:
            has_explicit_telco = any(
                brand in host_lower
                for brand in ['telstra', 'optus', 'tpg', 'vodafone', 'aussiebroadband', 'mobile', 'broadband']
            )
            if not has_explicit_telco:
                return False

        # EARLY REJECTION: Reject woolworthsmobile without Australian context
        if 'woolworthsmobile' in host_lower or 'woolworths' in host_lower:
            has_non_retail_signal = any(
                term in host_lower
                for term in ['telstra', 'optus', 'tpg', 'vodafone', 'webmail', 'mobile', 'broadband', 'nbn']
            )
            has_retail_signal = any(
                term in host_lower
                for term in ['gift', 'shop', 'store', 'reward', 'points', 'earn']
            )
            if has_retail_signal and not has_non_retail_signal:
                return False
        
        # EARLY REJECTION: Reject common English words matching "mate", "more", "material", etc.
        # unless they have EXPLICIT Australian telecom brand + action
        english_word_brands = {'mate', 'more', 'material', 'climate', 'automated', 'estimate', 'amber', 'lumo', 'commander', 'ovo', 'tangerine'}
        has_english_word = any(brand in host_lower for brand in english_word_brands)
        if has_english_word:
            # Must have BOTH Australian context AND telecom action terms
            has_explicit_aus_telco = any(
                brand in host_lower 
                for brand in ['telstra', 'optus', 'tpg', 'vodafone', 'aussiebroadband', 'iinet', 'dodo']
            )
            has_telecom_action = any(
                term in host_lower 
                for term in ['webmail', 'billing', 'bill', 'broadband', 'nbn', 'mobile', 'wireless', 'internet', 'telco']
            )
            has_au_tld = '.au' in host_lower or suffix_lower.endswith('.au')
            if not (has_explicit_aus_telco or (has_au_tld and has_telecom_action)):
                return False
        
        basic_context = has_au_suffix or '.au' in host_lower or 'austral' in host_lower or any(term in host_lower for term in UTILITY_GEO_TERMS)
        action_hit = has_utility_action()
        allowed_tld = suffix_lower in UTILITY_ALLOWED_TLDS
        # Reject non-Australian entities upfront
        if has_non_australian_entity(host_lower):
            return False
        for token in telecom_brand_tokens:
            if not token:
                continue
            if token in STRICT_TELECOM_BRANDS:
                # Vodafone and Aldi require explicit Australian context
                if token in ("vodafone", "aldi"):
                    has_explicit_au = (
                        has_au_suffix or
                        '.au' in host_lower or
                        'australia' in host_lower or 'australian' in host_lower or
                        any(state in host_lower for state in ['nsw', 'vic', 'qld', 'sa', 'wa', 'tas', 'act', 'nt'])
                    )
                    if not has_explicit_au:
                        continue
                if not (basic_context or action_hit):
                    continue
                # Use boundary matching first, then substring as fallback
                if _boundary_match(host_lower, token) or _boundary_match(rd_lower, token):
                    util_brand_raw = True
                    util_brand_confident = True
                    return True
                continue
            requires_context = token in REQUIRES_TELECOM_CONTEXT
            context_ok = basic_context or action_hit
            if _has_token(host_norm, token) or _has_token(rd_norm, token):
                if requires_context and not context_ok:
                    continue
                util_brand_raw = True
                util_brand_confident = True
                return True
        # Check TELECOM_NOISE_BYPASS brands with boundary matching
        for token in TELECOM_NOISE_BYPASS:
            if _boundary_match(host_lower, token) or _boundary_match(rd_lower, token):
                util_brand_raw = True
                util_brand_confident = True
                return True
        # Final fallback: check strict brands with boundary matching
        for token in STRICT_TELECOM_BRANDS:
            if _boundary_match(host_lower, token) or _boundary_match(rd_lower, token):
                # Vodafone requires explicit Australian context
                if token == "vodafone" and not (has_au_suffix or '.au' in host_lower or
                    'australia' in host_lower or 'australian' in host_lower):
                    continue
                util_brand_raw = True
                util_brand_confident = True
                return True
        return False

    brand_matched = has_telecom_brand()

    def has_gov_keyword():
        return contains_keyword(GOV_TOKENS_BOUNDARY)

    def has_gov_lure():
        return any(word in host_lower for word in GOV_LURE_KEYWORDS)

    def has_brand_hosting_combo():
        return any(token in host_lower for token in BRAND_HOSTING_TOKENS)

    def has_consumer_brand_signal():
        return any(tok in host_lower for tok in CONSUMER_BRAND_EXCLUDES) or \
               any(tok in rd_lower for tok in CONSUMER_BRAND_EXCLUDES)

    def has_bank_noise_token():
        return any(
            _has_token(host_norm, tok) or _has_token(rd_norm, tok) or
            _has_token(host_lower, tok) or _has_token(rd_lower, tok)
            for tok in BANKING_NOISE_TOKENS
        )

    host_label_list = [lbl for lbl in re.split(r'[.\-]', host_lower) if lbl]
    rd_label_list = [lbl for lbl in re.split(r'[.\-]', rd_lower) if lbl]
    combined_labels = set(host_label_list + rd_label_list)

    util_context_labels = {"au", "australia"}

    def has_util_context():
        if suffix_lower.endswith("au") or ext.suffix == "au":
            return True
        labels = host_label_list + rd_label_list
        if any(lbl in util_context_labels for lbl in labels):
            return True
        if any(lbl in UTILITY_GEO_TERMS for lbl in labels):
            return True
        if any(term in host_lower for term in UTILITY_GEO_TERMS):
            return True
        if has_utility_action():
            return True
        return False

    token_label_hints = {
        "australia", "gov",
        "revenue", "tax", "post"
    }
    for tok in token_label_hints:
        if _has_token(host_norm, tok) or _has_token(rd_norm, tok):
            combined_labels.add(tok)

    def has_australian_combo_signal():
        if 'australia' in combined_labels and combined_labels.intersection({'revenue', 'tax', 'ato', 'mygov'}):
            return True
        if 'gov' in combined_labels and 'australia' in combined_labels:
            return True
        if 'australia' in combined_labels and combined_labels.intersection({'post', 'auspost'}):
            return True
        if combined_labels.intersection({'ato', 'mygov', 'centrelink', 'medicare', 'ndis'}):
            return True
        return False

    # WHITELIST: honor user whitelist first (important: do this BEFORE any rejects)
    if is_whitelisted(host, rd):
        return None, "whitelist"

    # immediate drop: explicit .fr (after whitelist check)
    if ext.suffix and ext.suffix == "fr":
        return None, "tld_fr"

    # EARLY REJECTION: Generic phishing infrastructure (no Australian brand targeting)
    # This catches domains like account-12345.com, bafybei...ipfs, etc
    if GENERIC_PHISHING_PREFIXES.search(host):
        # Only reject if there's NO strong Australian brand indicator
        # Use boundary matching, not loose substring
        has_au_brand = (
            any(_boundary_match(host_lower, brand) or _boundary_match(rd_lower, brand)
                for brand in BANK_BRANDS + TELECOM_BRANDS + UTIL_BRANDS + AVIATION_BRANDS) or
            any(_has_token(host_norm, tok) for tok in STRONG_AUSTRALIAN_GOV)
        )
        if not has_au_brand:
            return None, "generic_phishing_infrastructure"

    # Check for non-Australian patterns EARLY (before any classification)
    is_non_au, pattern_category, matched_pattern = has_non_australian_patterns(host_lower)
    if is_non_au:
        return None, f"non_australian_pattern:{pattern_category}:{matched_pattern}"
    
    # SMART REJECTION: Use enhanced detection for non-Australian domains
    is_smart_non_au, smart_reason = is_smart_non_australian_domain(host_lower, ext)
    if is_smart_non_au:
        return None, f"smart_non_australian:{smart_reason}"
    
    # REJECT: IPFS/CID hashes (common in utilities feed false positives)
    if host.startswith('bafybei') or host.startswith('bafkre') or 'ipfs' in host_lower or 'dweb.link' in host_lower or 'nftstorage.link' in host_lower:
        has_au_brand = any(
            _boundary_match(host_lower, brand) or _boundary_match(rd_lower, brand)
            # Added Qantas aliases that were previously rejected
            for brand in ['qantas', 'qf', 'jetstar', 'virgin', 'ausgrid', 'originenergy', 'agl',
                         'qantareward', 'qantasairline', 'qantascredit-home', 'qantasgiftprogram',
                         'qantasmoney-reward', 'qantaspoints', 'qantasrdws2025', 'qantasredem',
                         'qantasrewards', 'qantelyx']
        )
        if not has_au_brand:
            return None, "ipfs_cid_hash"

    if has_consumer_brand_signal():
        return None, "consumer_brand_signal"

    # REJECT crypto/web3 wallet phishing (common false positive for government)
    # Check this EARLY, before noise host check (pages.dev/webflow.io would return first)
    crypto_wallet_patterns = [
        'uphold-wallet', 'wallet-meta', 'wallet-support-ledger', 'sol-incinerator',
        'support---ledgr', 'support--blockfi', 'support--sso--coinbase',
        'support-ledger-cdn', 'support-en--ledgr', 'support-docs-trzor',
        'wallet-meta-support', 'uphold-cdn-support', 'support-uphold-cdn',
        'support--ledgr-io', 'support-en--ledgr-io', 'support-tzr-waltt',
        'auth-cdn-bitbuy', 'en-support-uphold',
        'metamask', 'mate-mask', 'matemask', 'mateimask',
        'trustwallet', 'trust-wallet', 'atomicwallet', 'atomic-wallet',
    ]
    if any(pattern in host_lower for pattern in crypto_wallet_patterns):
        return None, "crypto_wallet_not_australian"

    # REJECT non-Australian government imposters (US IRS, UK HMRC, etc.)
    non_au_gov_imposters = [
        'irs-gov', 'irs-gov-refund', 'sa-www4-irs', 'internal-revenue-service',
        'hmrc', 'hm-revenue', 'hmcustoms', 'gov-uk', 'gov.uk',
        'dvla', 'hm-revenue-customs', 'rebate.ie',
    ]
    if any(pattern in host_lower for pattern in non_au_gov_imposters):
        return None, "non_australian_gov_imposter"

    # REJECT ABN AMRO Dutch bank (m15xABN pattern — "abn" matches Australian ABN keyword)
    if re.search(r'm15\d+abn', host_lower):
        return None, "abn_amro_dutch_not_australian"

    # REJECT Cloudflare R2 storage URLs (pub-*.r2.dev — random hashes often contain brand-like strings)
    if host_lower.endswith('.r2.dev') or '.r2.dev' in host_lower:
        return None, "cloudflare_r2_storage"

    # AGGRESSIVE FALSE POSITIVE REJECTION (before any weak pattern matching)
    # Reject pure "spin", "bnb", "boost" domains without explicit Australian telecom brand
    # "boost" is too generic (crypto, DeFi, marketing) — never counts as explicit brand
    if any(term in host_lower for term in ['spin', 'bnb', 'boost']):
        has_explicit_aus_telco = any(
            brand in host_lower
            for brand in ['telstra', 'optus', 'tpg', 'vodafone', 'aussiebroadband', 'iinet', 'dodo', 'iinetwest', 'westnet']
        )
        has_telecom_action = any(
            term in host_lower
            for term in ['webmail', 'billing', 'bill', 'broadband', 'nbn', 'mobile', 'wireless']
        )
        if not (has_explicit_aus_telco or has_telecom_action):
            return None, "spin_bnb_boost_false_positive"

    # quick: drop known tracking-first hostnames (prefixes) for non-whitelisted hosts
    for p in REJECT_PREFIXES:
        if host.startswith(p):
            return None, f"prefix_reject:{p}"

    # Also drop if the first label is a tracking keyword
    first_label = host.split(".")[0]
    if any(k in first_label for k in REJECT_SUBDOMAIN_KEYWORDS):
        return None, "first_label_tracking"

    if has_brand_hosting_combo():
        # REJECT IPFS/decentralized hosting for non-Australian brands
        if any(term in host_lower for term in ['siasky', 'ipfs', 'dweb', 'nftstorage', 'infura']):
            return None, "ipfs_hosting_provider"
        
        if has_bank_keyword() or BOUNDARY_BANKING.search(host) or BOUNDARY_BANKING.search(rd):
            if has_au_suffix or has_australian_context(host, ext, rd):
                return "banking", "banking_hosting_combo"
            else:
                return None, "banking_hosting_combo_no_australian_context"
        if brand_matched or BOUNDARY_UTIL.search(host) or BOUNDARY_UTIL.search(rd):
            if has_au_suffix or has_australian_context(host, ext, rd):
                return "utilities", "util_hosting_combo"
            else:
                return None, "util_hosting_combo_no_australian_context"
        if has_gov_keyword():
            if has_au_suffix or has_australian_context(host, ext, rd):
                return "government", "gov_hosting_combo"
            else:
                return None, "gov_hosting_combo_no_australian_context"

    if has_au_suffix and any(token in host_lower for token in PHISHING_ACTION_TOKENS):
        if has_bank_keyword() or BOUNDARY_BANKING.search(host) or BOUNDARY_BANKING.search(rd):
            return "banking", "au_suffix_action_bank"
        if brand_matched or BOUNDARY_TELECOM.search(host) or BOUNDARY_TELECOM.search(rd):
            return "utilities", "au_suffix_action_util"
        gov_match = has_gov_keyword() or has_australian_combo_signal()
        gov_signal = has_gov_lure() or BOUNDARY_LURE.search(host_norm) or BOUNDARY_LURE.search(rd_norm)
        if gov_match and gov_signal and not has_consumer_brand_signal():
            return "government", "au_suffix_action_gov"

    # Australian strong government brands for root validation
    TRACK_TOKENS = {"track","tracking","redelivery","delivery","reschedule","parcel","stats","smetrics","sslstats","smetric","strack","trk","sentry"}

    # helper: require strong australian root (not just .au)
    def has_strong_australian_root():
        if rd.endswith(".gov.au") or rd.endswith(".australia.gov.au"):
            return True
        if any(_has_token(rd_norm, k) for k in STRONG_AUSTRALIAN_GOV):
            return True
        if rd in OFFICIAL_WHITELIST:
            return True
        # Additional check for strong Australian context
        if any(_has_token(rd_norm, k) for k in STRONG_AUSTRALIAN_GOV):
            return True
        # Only unambiguous state tokens count as strong root
        if any(lbl in UNAMBIGUOUS_STATE_TOKENS for lbl in rd_label_list):
            return True
        # Ambiguous state tokens need extra Australian signal
        if any(lbl in AMBIGUOUS_STATE_TOKENS for lbl in rd_label_list):
            has_extra = (
                any(_has_token(rd_norm, k) for k in STRONG_AUSTRALIAN_GOV) or
                any(_has_token(rd_norm, k) for k in AUSTRALIAN_LONG_KEYWORDS if len(k) >= 6) or
                rd_norm.endswith(".au")
            )
            if has_extra:
                return True
        return False

    # 2) numeric-prefix domain names (common DGA/automated), e.g. "39928-australia.com"
    if re.match(r'^\d{2,}[-.]', host):
        if not has_strong_australian_root():
            return None, "numeric_prefix"

    # 3) drop hosts where strong gov token is only in subdomain and rd lacks australian context
    token_in_host = any(_has_token(host_norm, k) for k in STRONG_AUSTRALIAN_GOV)
    token_in_rd   = any(_has_token(rd_norm, k) for k in STRONG_AUSTRALIAN_GOV)
    if token_in_host and not token_in_rd:
        if not has_strong_australian_root() and not has_australian_context(host, ext, rd):
            return None, "strong_token_only_subdomain_no_root"

    # 4) skip overly long host labels (likely cname chains / trackers)
    if host.count('.') >= 4 and not (BOUNDARY_BANKING.search(rd) or BOUNDARY_TELECOM.search(rd) or BOUNDARY_UTIL.search(rd)):
        return None, "too_many_labels"

    # Enhanced Australian state token detection - more sensitive to Australian context
    if has_australian_state_token(host_lower) or has_australian_state_token(rd_lower):
        if (has_bank_keyword() or BOUNDARY_BANKING.search(host) or BOUNDARY_BANKING.search(rd)) and (has_au_suffix or has_australian_context(host, ext, rd)):
            return "banking", "banking_state_combo"
        if (brand_matched or BOUNDARY_TELECOM.search(host) or BOUNDARY_TELECOM.search(rd)) and (has_au_suffix or has_australian_context(host, ext, rd)):
            return "utilities", "telecom_state_combo"
        if (has_gov_keyword() or has_gov_lure() or has_australian_combo_signal()) and has_australian_context(host, ext, rd) and not has_consumer_brand_signal():
            return "government", "gov_state_combo"
        if BOUNDARY_UTIL.search(host) or BOUNDARY_UTIL.search(rd) or BOUNDARY_UTIL.search(host_norm) or BOUNDARY_UTIL.search(rd_norm):
            if has_australian_context(host, ext, rd):
                return "utilities", "util_state_combo"
            else:
                return None, "util_state_combo_no_australian_context"


    # 5) explicit excludes / noisy host providers
    # CRITICAL EXCLUDES: Always reject these regardless of Australian context
    critical_excludes = [
        'kleinanzeigen', 'finanzinvest', 'knab', 'antiriciclaggio',
        'hmrc', 'hm-revenue', 'dvla', 'gov.uk', 'irs',
        'metamask', 'matemask', 'uphold-wallet', '365online',
        # Flip/gaming false positives
        '2flip6', '-flip', 'flip6', 'flip7', 'flips.cn',
        # Free hosting providers
        'hsforms.com',
        # Generic account-support domains
        'account-support.info', 'account-support.dynamic-dns.net', 'account-support.redirectme.net',
    ]
    if any(pattern in host_lower for pattern in critical_excludes):
        return None, "critical_exclude"
    
    # Other excludes - reject domains matching known non-Australian patterns
    # For generic words (orange, free, etc.) allow Australian context override
    # For specific non-AU brand patterns, reject unconditionally
    if BOUNDARY_EXCL.search(host) or BOUNDARY_EXCL.search(rd) or \
       BOUNDARY_EXCL.search(host_norm) or BOUNDARY_EXCL.search(rd_norm) or \
       BOUNDARY_EXCL_REGEX.search(host) or BOUNDARY_EXCL_REGEX.search(rd):
        # Only allow through for domains with genuine Australian connection
        # that is NOT just the excluded brand name itself
        # Check for: real .au TLD, gov tokens, or state abbreviations
        # (NOT telecom/bank brands, since the exclude patterns ARE telecom/bank brands)
        has_genuine_au_connection = (
            suffix_lower.endswith("au") or
            any(_has_token(host, tok) for tok in STRONG_AUSTRALIAN_GOV) or
            any(_has_token(host, tok) for tok in UNAMBIGUOUS_STATE_TOKENS) or
            has_australian_state_token(host)
        )
        if has_genuine_au_connection:
            pass
        else:
            return None, "explicit_exclude"
    
    if is_noise_host(host):
        # For noise hosts, be more lenient if we detect Australian brands or context
        if (any(_has_token(host_norm, tok) or _has_token(rd_norm, tok) for tok in TELECOM_NOISE_BYPASS) or
            any(_has_token(host_norm, tok) or _has_token(rd_norm, tok) for tok in BANK_NOISE_BYPASS) or
            brand_matched or has_bank_keyword()):
            if has_australian_context(host, ext, rd):
                # Determine category based on what we found
                if any(_has_token(host_norm, tok) or _has_token(rd_norm, tok) for tok in TELECOM_NOISE_BYPASS):
                    return "utilities", "telecom_noise_host"
                elif any(_has_token(host_norm, tok) or _has_token(rd_norm, tok) for tok in BANK_NOISE_BYPASS):
                    return "banking", "bank_noise_host"
                elif brand_matched:
                    return "utilities", "telecom_brand_noise"
                elif has_bank_keyword():
                    return "banking", "bank_keyword_noise"
        
        # For other noise hosts without clear Australian context, still reject
        return None, "noise_host_provider"

    # 6) tracking/stat tokens require strong australian root to be kept
    if any(tok in host_norm for tok in TRACK_TOKENS):
        if not has_strong_australian_root():
            return None, "track_token_no_strong_root"
        # if strong root but subdomain looks like analytics, drop unless whitelisted (we already whitelist earlier)
        if any(host.startswith(p) for p in ("stats.", "sslstats.", "smetrics.", "smetric.", "strack.", "sstat.", "sentry.")):
            return None, "track_sub_on_strong_root"

    # 7) banking heuristics - require Australian context
    # BANKING FALSE POSITIVE REJECTION: Reject generic account/banking domains
    if BOUNDARY_BANKING.search(host) or BOUNDARY_BANKING.search(rd) or \
       BOUNDARY_BANKING.search(host_norm) or BOUNDARY_BANKING.search(rd_norm):
        # Reject non-Australian entities
        if has_non_australian_entity(host_lower):
            return None, "non_australian_entity"
        
        # Reject Italian ING (anti-money laundering scams)
        if any(p in host_lower for p in ['antiriciclaggio', 'questionario', 'normativa']):
            return None, "italian_ing_not_australian"
        
        # Reject German banks/classifieds
        if any(p in host_lower for p in ['kleinanzeigen', 'finanzinvest', 'biglobe']):
            return None, "german_bank_not_australian"
        
        # Reject Dutch banks
        if 'knab' in host_lower:
            return None, "dutch_bank_not_australian"
        
        # Reject generic banking without Australian brand
        has_aus_bank_brand = any(
            _boundary_match(host_lower, brand) or _boundary_match(rd_lower, brand)
            for brand in BANK_BRANDS
        )
        if not has_aus_bank_brand:
            # Only allow if it has .au TLD AND banking action terms
            if has_au_suffix and any(term in host_lower for term in ['login', 'secure', 'verify', 'account']):
                return "banking", "generic_bank_with_au_suffix"
            return None, "generic_banking_no_aus_brand"
        
        if has_bank_noise_token() and not has_australian_context(host, ext, rd):
            return None, "bank_noise_token"
        if has_au_suffix or has_australian_context(host, ext, rd):
            return "banking", "banking_match"
        else:
            return None, "bank_no_australian_context"
    
    if has_bank_keyword():
        # Reject non-Australian entities
        if has_non_australian_entity(host_lower):
            return None, "non_australian_entity"
        
        # Reject generic "bank" keyword without Australian brand
        has_aus_bank_brand = any(
            brand in host_lower 
            for brand in ['commbank', 'cba', 'westpac', 'nab', 'anz', 'macquarie', 
                         'commonwealth', 'bendigobank', 'suncorp', 'bankwest']
        )
        if not has_aus_bank_brand:
            # Require both .au TLD AND Australian context
            if not (has_au_suffix and has_australian_context(host, ext, rd)):
                return None, "generic_bank_keyword_no_aus_brand"
        
        if has_bank_noise_token() and not has_australian_context(host, ext, rd):
            return None, "bank_noise_token"
        if has_au_suffix or has_australian_context(host, ext, rd):
            return "banking", "bank_keyword_match"
        else:
            return None, "bank_no_australian_context"

    # WEAK BANKING: Only accept if has Australian context AND brand
    if any(_has_token(host, w) for w in WEAK_BANKING):
        # Reject non-Australian entities
        if has_non_australian_entity(host_lower):
            return None, "non_australian_entity"
        # If this looks like a government domain (contains mygov, ato, etc.), prioritize government classification
        if any(_has_token(host_norm, gov_kw) for gov_kw in GOV_TOKENS_BOUNDARY):
            if has_australian_context(host, ext, rd):
                return "government", "gov_priority_over_banking"

        if has_consumer_brand_signal():
            return None, "consumer_brand_signal"
        
        # Stricter: require BOTH Australian context AND banking/telecom brand
        has_aus_brand = any(
            _boundary_match(host_lower, brand) or _boundary_match(rd_lower, brand)
            for brand in BANK_BRANDS + TELECOM_BRANDS
        )
        if has_australian_context(host, ext, rd) and has_aus_brand:
            if has_gov_keyword():
                return "government", "weak_banking_gov_override"
            if brand_matched:
                return "utilities", "weak_banking_util_override"
            return "banking", "weak_banking_with_context"
        # Without both context and brand, reject
        return None, "weak_banking_no_context_or_brand"



    # 9) Strong Australian government brands - require explicit Australian context
    strong_gov_keywords = {"ato", "abn", "mygov", "centrelink", "medicare", "ndis", "myagedcare", "serviceaustralia"}
    has_strong_gov_keyword = any(_has_token(host_norm, k) or _has_token(rd_norm, k) for k in strong_gov_keywords)
    if has_strong_gov_keyword:
        # Reject non-Australian entities (e.g., ABN AMRO Dutch bank)
        if has_non_australian_entity(host_lower):
            return None, "non_australian_entity"
        # For short tokens like ABN, require explicit Australian indicators
        short_gov_tokens = {"abn", "ato", "ndis"}
        has_short_token = any(_has_token(host_norm, k) or _has_token(rd_norm, k) for k in short_gov_tokens)
        if has_short_token:
            # Require .au TLD or explicit Australian keywords in domain
            # OR gov-specific action terms (tax, tfn, bas, etc.)
            has_gov_action = any(
                term in host_lower
                for term in ['tax', 'tfn', 'bas', 'payg', 'gst', 'super',
                            'superannuation', 'return', 'lodgement', 'lodgment',
                            'abr', 'abn', 'mygov', 'centrelink', 'medicare']
            )
            has_explicit_au = (
                has_au_suffix or
                'australia' in host_lower or 'australian' in host_lower or
                '.au' in host_lower or '-au' in host_lower or
                any(state in host_lower for state in UNAMBIGUOUS_STATE_TOKENS) or
                has_gov_action
            )
            if not has_explicit_au:
                return None, "short_gov_token_no_explicit_au"
        if has_gov_lure() or any(tok in host_lower for tok in PHISHING_ACTION_TOKENS):
            return "government", "strong_gov_keyword_match"
        # Even without action tokens, strong gov brands alone are suspicious
        return "government", "strong_gov_brand_only"

    # GOVERNMENT FALSE POSITIVE REJECTION
    # Reject UK HMRC, US IRS/state revenue, Canadian CRA domains
    non_au_gov_patterns = [
        'hmrc', 'hm-revenue', 'dvla', 'gov-uk', 'gov.uk', 'gov\\.uk-',
        'irs', 'irs-gov', 'utah-gov', 'ohio-revenue', 'phila.revenue',
        'canada-revenue', 'cra-arc', 'revenue-agency', 'hmcustoms', 'hmveservice',
        'rebate.ie', 'santander\\.', 'wellsfargo', 'neteller'
    ]
    if any(re.search(pattern, host_lower, re.IGNORECASE) for pattern in non_au_gov_patterns):
        return None, "non_australian_government"
    
    # Reject Microsoft 365 / Office 365 phishing (not Australian gov)
    if any(pattern in host_lower for pattern in ['365online', 'office365', '365web']):
        return None, "microsoft365_not_australian_gov"
    
    # Reject AIB Ireland
    if 'aib' in host_lower and not any(p in host_lower for p in ['mygov', 'ato', 'centrelink', 'medicare']):
        if any(p in host_lower for p in ['aib-online', 'aibsecure', 'aib-auth', 'aibsecuresupport']):
            return None, "aib_ireland_not_australian"
    
    # Reject crypto/wallet phishing
    crypto_patterns = [
        'uphold-wallet', 'wallet-meta', 'wallet-support-ledger', 'sol-incinerator',
        'support---ledgr', 'support--blockfi', 'support--sso--coinbase'
    ]
    if any(pattern in host_lower for pattern in crypto_patterns):
        return None, "crypto_wallet_not_government"
    
    # Reject generic account support domains without Australian brand (UNCONDITIONAL)
    if 'account-support' in host_lower or 'accountsupport' in host_lower:
        has_aus_gov_brand = any(
            brand in host_lower 
            for brand in ['mygov', 'ato', 'centrelink', 'medicare', 'ndis', 'auspost', 'servicesaustralia']
        )
        has_aus_telco_brand = any(
            brand in host_lower 
            for brand in ['telstra', 'optus', 'tpg', 'vodafone', 'aussiebroadband']
        )
        if not has_aus_gov_brand and not has_aus_telco_brand:
            return None, "generic_account_support"
    
    # Reject generic "support" domains without any Australian context
    if host_lower.count('support') >= 2 and not any(p in host_lower for p in ['mygov', 'ato', 'centrelink', 'medicare', 'telstra', 'optus']):
        if not any(p in host_lower for p in ['.au', '-au', 'australia']):
            if any(p in host_lower for p in ['account-support', 'support-account', 'support-center']):
                return None, "generic_support_domain_not_australian"

    # Reject generic "tax", "revenue" without Australian context
    if any(term in host_lower for term in ['tax', 'revenue']):
        has_au_context = (
            has_au_suffix or
            'australia' in host_lower or 'australian' in host_lower or
            '.au' in host_lower or '-au' in host_lower or
            any(token in host_lower for token in ['ato', 'mygov', 'abr', 'tfn', 'gst']) or
            any(state in host_lower for state in UNAMBIGUOUS_STATE_TOKENS)
        )
        if not has_au_context:
            return None, "generic_tax_revenue_no_au_context"

    # 9b) weak government cues — require australian context (looser than strong root)
    weak_gov = [
        "tax","gst","parcel","delivery","redelivery","postoffice","shipment",
        "tracking","track","reschedule", "revenue", "taxation"
    ]
    if any(w in host for w in weak_gov) or any(_has_token(host, w) for w in weak_gov):
        # Reject non-Australian entities and patterns early
        if has_non_australian_entity(host_lower):
            return None, "non_australian_entity"
        is_non_au, pattern_cat, pattern = has_non_australian_patterns(host_lower)
        if is_non_au:
            return None, f"non_australian_pattern_{pattern_cat}"
        gov_match = has_gov_keyword()
        lure_or_action = has_gov_lure() or any(tok in host_lower for tok in PHISHING_ACTION_TOKENS)
        if (has_au_suffix or has_australian_context(host, ext, rd)) and gov_match and lure_or_action and not has_consumer_brand_signal():
            return "government", "gov_weak_with_context"

    health_transfer_keywords = {"health.gov.au", "myagedcare", "ndis"}
    if any(_has_token(host_norm, k) for k in health_transfer_keywords):
        if any(term in host_lower for term in ("payment", "transfer")):
            if has_australian_context(host, ext, rd):
                return "government", "gov_health_transfer"


    # TELECOM FALSE POSITIVE REJECTION
    # Reject domains that match "spin" (gaming), "bnb" (Airbnb/crypto), or "boost" (generic marketing)
    # "boost" is too generic (crypto, DeFi, marketing) — never counts as explicit brand
    # unless they have explicit Australian telecom brand indicators
    if any(term in host_lower for term in ['spin', 'bnb', 'boost']):
        # Check if it has explicit Australian telecom brand
        has_aus_telco = any(
            brand in host_lower
            for brand in ['telstra', 'optus', 'tpg', 'vodafone', 'aussiebroadband', 'iinet', 'dodo']
        )
        # Check if it has telecom action terms (billing, webmail, etc)
        has_telecom_action = any(
            term in host_lower
            for term in ['webmail', 'billing', 'refund', 'bill', 'broadband', 'nbn', 'mobile', 'wireless']
        )
        # Allow .au TLD as additional signal
        has_au_tld = suffix_lower.endswith("au")
        if not (has_aus_telco or has_telecom_action or has_au_tld):
            return None, "spin_bnb_boost_false_positive"

    # 10) telecom heuristics - more inclusive for obvious phishing
    telecom_token_hit = (
        BOUNDARY_TELECOM.search(host) or BOUNDARY_TELECOM.search(rd) or
        BOUNDARY_TELECOM.search(host_norm) or BOUNDARY_TELECOM.search(rd_norm)
    )
    telecom_keyword_hit = brand_matched
    
    # Check for obvious telco phishing patterns first
    # Use boundary matching to avoid false positives like "utpgu.com" matching "tpg"
    telco_phishing_indicators = ['telstra', 'optus', 'vodafone', 'aussiebroadband', 'tpg']

    # If we have telco keywords and phishing indicators, be more inclusive
    has_phishing_indicators = any(indicator in host_lower for indicator in [
        'login', 'secure', 'account', 'verify', 'update', 'alert', 'notice',
        'refund', 'billing', 'payment', 'signin', 'suspend', 'webmail'
    ])

    # Use boundary matching for telco indicators (not loose substring)
    has_telco_indicator = any(
        _boundary_match(host_lower, telco) or _boundary_match(rd_lower, telco) or
        _has_token(host_norm, telco) or _has_token(rd_norm, telco)
        for telco in telco_phishing_indicators
    )

    if telecom_token_hit or telecom_keyword_hit or has_telco_indicator:
        
        # Reject non-Australian entities
        if has_non_australian_entity(host_lower):
            return None, "non_australian_entity"
        
        # Aldi requires explicit Australian mobile context
        if "aldi" in host_lower:
            is_au_mobile = (
                '.au' in host_lower or
                'mobile' in host_lower
            )
            if not is_au_mobile:
                return None, "aldi_no_explicit_au"
        
        # If we have obvious phishing indicators, be more inclusive
        if has_phishing_indicators and has_telco_indicator:
            return "utilities", "telecom_phishing_pattern"

        # For other cases, require some Australian context
        if has_util_context() or has_australian_context(host, ext, rd) or has_au_suffix:
            return "utilities", "telecom_match"

        # If we have telco brand but no clear Australian context, check for common phishing patterns
        if has_telco_indicator:
            common_phishing_suffixes = [
                'blogspot.com', 'weebly.com', 'wordpress.com', 'flutterflow.app',
                'deno.dev', 'netlify.app', 'vercel.app', 'github.io'
            ]
            if any(host_lower.endswith(suffix) for suffix in common_phishing_suffixes):
                return "utilities", "telecom_common_phishing_pattern"

    if util_brand_confident or util_brand_raw:
        # Aldi requires explicit Australian mobile context
        if "aldi" in host_lower:
            is_au_mobile = (
                '.au' in host_lower or
                'mobile' in host_lower
            )
            if not is_au_mobile:
                return None, "aldi_no_explicit_australian_context"
        if has_au_suffix or has_australian_context(host, ext, rd):
            return "utilities", "telecom_brand_fallback"
        else:
            return None, "telecom_no_australian_context"

    # 10b) utilities heuristics - require Australian context
    utilities_token_hit = (
        BOUNDARY_UTIL.search(host) or BOUNDARY_UTIL.search(rd) or
        BOUNDARY_UTIL.search(host_norm) or BOUNDARY_UTIL.search(rd_norm)
    )
    if utilities_token_hit:
        # UTILITIES FALSE POSITIVE REJECTION
        # Reject generic "synergy" domains (not Australian energy company)
        if 'synergy' in host_lower and not any(term in host_lower for term in ['australia', 'perth', 'wa-', '-au', '.au']):
            return None, "generic_synergy_no_au_context"
        
        # Reject hosting provider domains
        if any(term in host_lower for term in ['siasky', 'ipfs', 'dweb', 'nftstorage']):
            return None, "utilities_hosting_provider"
        
        # Reject "amber" that's not Amber Energy (e.g. amber-drift, personal names)
        if 'amber' in host_lower and not any(term in host_lower for term in ['amber.com.au', 'amberenergy', 'amber.energy']):
            if any(term in host_lower for term in ['amber-drift', 'poindexter', 'hopeful-amber']):
                return None, "generic_amber_not_energy"
        
        # Reject "lumo" that's not Lumo Energy (AI models, crypto)
        if 'lumo' in host_lower and not any(term in host_lower for term in ['lumo.com.au', 'lumoenergy']):
            if any(term in host_lower for term in ['lumo-8b', 'lumo-nexora', 'saint-lumo']):
                return None, "generic_lumo_not_energy"
        
        # Reject "commander" that's not Commander Energy (French health cards, generic)
        if 'commander' in host_lower and not any(term in host_lower for term in ['commander.com.au', 'commanderenergy']):
            if any(term in host_lower for term in ['commander-carte', 'commander-mule']):
                return None, "generic_commander_not_energy"
        
        # Reject "ovo" that's not OVO Energy (generic subdomains)
        if 'ovo' in host_lower and len(host_lower) < 15 and not 'ovo.com.au' in host_lower:
            return None, "generic_ovo_not_energy"
        
        if has_au_suffix or has_australian_context(host, ext, rd):
            return "utilities", "utilities_match"
        else:
            return None, "utilities_no_australian_context"

    # Aviation heuristics - now merged into utilities
    # AVIATION FALSE POSITIVE REJECTION: Reject non-Australian airlines
    aviation_token_hit = (
        BOUNDARY_AVIATION.search(host) or BOUNDARY_AVIATION.search(rd) or
        BOUNDARY_AVIATION.search(host_norm) or BOUNDARY_AVIATION.search(rd_norm)
    )
    if aviation_token_hit:
        # Reject non-Australian airlines (Ryanair, EasyJet, Lufthansa, etc)
        non_au_airlines = ['ryanair', 'easyjet', 'lufthansa', 'airfrance', 'klm', 'british-airways', 'emirates']
        if any(airline in host_lower for airline in non_au_airlines):
            return None, "non_australian_airline"
        
        # For Australian airlines, require either Australian context OR booking/action terms
        has_aviation_action = any(
            term in host_lower 
            for term in AVIATION_ACTION_TERMS
        )
        
        if has_australian_context(host, ext, rd) or has_aviation_action:
            return "utilities", "aviation_match"
        else:
            # Without context or action terms, be conservative
            return None, "aviation_no_context_or_action"

    # 11) weak brand + lure combos - require Australian context
    if (BOUNDARY_WEAK.search(host) or BOUNDARY_WEAK.search(rd) or \
        BOUNDARY_WEAK.search(host_norm) or BOUNDARY_WEAK.search(rd_norm)) and \
       (BOUNDARY_LURE.search(host) or BOUNDARY_LURE.search(rd) or \
        BOUNDARY_LURE.search(host_norm) or BOUNDARY_LURE.search(rd_norm)):
        # Reject non-Australian entities
        if has_non_australian_entity(host_lower):
            return None, "non_australian_entity"
        if has_australian_context(host, ext, rd):
            if (_has_token(host_norm, "ato") or _has_token(host_norm, "mygov")) and any(k in host_norm for k in ["australia","au","auspost"]):
                return "government", "weakcombo_ato"
            if ("telstra" in host_norm or "optus" in host_lower) and any(k in host_norm for k in ["australia","au"]):
                return "utilities", "weakcombo_telstra_optus"
            # Enhanced: also look for other combinations that could indicate phishing
            if any(token in host_norm for token in ["australia", "gov", "serviceaustralia", "revenue"]) and any(lure in host_norm for lure in ["login", "secure", "account", "verify", "auth"]):
                return "government", "weakcombo_australia_auth"


    return None, "no_rule_match"

# ---------------------------
# Helpers for feed maintenance
# ---------------------------
def archive_existing_feeds(exclude_filenames=None):
    exclude_filenames = exclude_filenames or set()
    for old_file in os.listdir(OUTPUT_DIR):
        if not old_file.endswith(".txt"):
            continue
        if old_file in exclude_filenames:
            continue
        old_path = os.path.join(OUTPUT_DIR, old_file)
        new_path = os.path.join(ARCHIVE_DIR, old_file)
        try:
            os.rename(old_path, new_path)
            print(f"📦 Archived old feed: {old_file}")
        except Exception as e:
            print(f"⚠️ Failed to archive {old_file}: {e}")

def _load_latest_feed(category):
    pattern = os.path.join(OUTPUT_DIR, f"australian_phish_{category}_*.txt")
    matches = sorted(glob.glob(pattern))
    if not matches:
        return set()
    latest = matches[-1]
    with open(latest, encoding="utf-8") as fh:
        return {line.strip() for line in fh if line.strip()}


def reclassify_existing_feeds():
    original = {cat: _load_latest_feed(cat) for cat in ("banking", "government", "utilities")}
    # Also load old telecom feed if it exists and merge into combined
    telecom_feed = _load_latest_feed("telecom")
    combined = set().union(*original.values(), telecom_feed)
    if not combined:
        print("⚠️ No existing feeds found to reclassify.")
        return

    new_sets = {"banking": set(), "government": set(), "utilities": set()}
    dropped = []

    for host in sorted(combined):
        cat, reason = classify_host(host)
        if cat in new_sets:
            new_sets[cat].add(host)
        else:
            dropped.append((host, reason))

    today = datetime.now().strftime("%Y-%m-%d")
    archive_existing_feeds(exclude_filenames={os.path.basename(REJECTIONS_LOG)})

    outputs = {
        "banking": os.path.join(OUTPUT_DIR, f"australian_phish_banking_{today}.txt"),
        "government": os.path.join(OUTPUT_DIR, f"australian_phish_government_{today}.txt"),
        "utilities": os.path.join(OUTPUT_DIR, f"australian_phish_utilities_{today}.txt"),
    }

    for cat, path in outputs.items():
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(new_sets[cat])))
        print(f"🔄 Rewrote {cat} feed with {len(new_sets[cat])} hosts → {path}")

    if dropped:
        dropped_log = os.path.join(OUTPUT_DIR, "reclassified_dropped.txt")
        with open(dropped_log, "w", encoding="utf-8") as fh:
            fh.write("host\treject_reason\n")
            for host, reason in dropped:
                fh.write(f"{host}\t{reason}\n")
        print(f"⚠️ Dropped {len(dropped)} hosts during reclassification → {dropped_log}")

def _find_feed_file(category, date_str, directory):
    filename = f"australian_phish_{category}_{date_str}.txt"
    filepath = os.path.join(directory, filename)
    if os.path.exists(filepath):
        return filepath
    return None

def _load_domains_from_file(filepath):
    if not filepath or not os.path.exists(filepath):
        return set()
    with open(filepath, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}

def _get_latest_and_previous_feed_dates(category):
    all_feed_files = []
    # Search in OUTPUT_DIR
    pattern_output = os.path.join(OUTPUT_DIR, f"australian_phish_{category}_*.txt")
    all_feed_files.extend(glob.glob(pattern_output))

    # Search in ARCHIVE_DIR
    pattern_archive = os.path.join(ARCHIVE_DIR, f"australian_phish_{category}_*.txt")
    all_feed_files.extend(glob.glob(pattern_archive))

    # Extract dates and sort them
    dates = []
    for fpath in all_feed_files:
        match = re.search(r"\d{4}-\d{2}-\d{2}", os.path.basename(fpath))
        if match:
            dates.append(datetime.strptime(match.group(0), "%Y-%m-%d"))

    dates = sorted(list(set(dates)))

    if not dates or len(dates) < 2:
        return None, None # Not enough data for comparison

    latest_date = dates[-1]
    previous_date = dates[-2]

    return latest_date.strftime("%Y-%m-%d"), previous_date.strftime("%Y-%m-%d")


def compare_feed_runs(date1_str=None, date2_str=None):
    categories = ["banking", "government", "utilities"]
    
    print("\n📊 Initiating Feed Comparison...")

    for category in categories:
        print(f"\n--- Comparing {category.capitalize()} Feeds ---")

        if date1_str is None or date2_str is None:
            # Determine latest and previous dates automatically
            latest_date, previous_date = _get_latest_and_previous_feed_dates(category)
            if latest_date is None or previous_date is None:
                print(f"⚠️ Not enough historical data to compare {category} feeds automatically.")
                continue
            compare_date1_str = latest_date
            compare_date2_str = previous_date
            print(f"Comparing latest ({compare_date1_str}) with previous archived ({compare_date2_str}).")
        else:
            compare_date1_str = date1_str
            compare_date2_str = date2_str
            print(f"Comparing {compare_date1_str} with {compare_date2_str}.")

        # Try to find files in OUTPUT_DIR first, then ARCHIVE_DIR
        file1_path = _find_feed_file(category, compare_date1_str, OUTPUT_DIR) or \
                     _find_feed_file(category, compare_date1_str, ARCHIVE_DIR)
        file2_path = _find_feed_file(category, compare_date2_str, ARCHIVE_DIR) # Previous is usually in archive

        if not file1_path:
            print(f"❌ File not found for {category} on {compare_date1_str}. Skipping comparison.")
            continue
        if not file2_path:
            print(f"❌ File not found for {category} on {compare_date2_str}. Skipping comparison.")
            continue

        domains1 = _load_domains_from_file(file1_path)
        domains2 = _load_domains_from_file(file2_path)

        if not domains1 and not domains2:
            print("   No domains in either file. No comparison to perform.")
            continue
        
        # Calculate differences
        new_in_1 = domains1 - domains2
        removed_in_2 = domains2 - domains1
        common_domains = domains1 & domains2

        total_in_1 = len(domains1)
        total_in_2 = len(domains2)

        # Display results in a table format
        print(f"\n{category.capitalize()} Feed Comparison:")
        print("+" + "-" * 60 + "+")
        print(f"| {'Date':<20} | {'Total Domains':<15} | {'New Domains':<10} | {'Removed Domains':<10} |")
        print("+" + "-" * 60 + "+")
        
        if total_in_1 > 0:
            percent_new = (len(new_in_1) / total_in_1) * 100
        else:
            percent_new = 0.00
        
        if total_in_2 > 0:
            percent_removed = (len(removed_in_2) / total_in_2) * 100
        else:
            percent_removed = 0.00
        
        print(f"| {compare_date1_str:<20} | {total_in_1:<15} | {len(new_in_1):<10} | {'N/A':<10} |")
        print(f"| {compare_date2_str:<20} | {total_in_2:<15} | {'N/A':<10} | {len(removed_in_2):<10} |")
        print("+" + "-" * 60 + "+")
        
        if new_in_1:
            print("\nNew domains found:")
            for domain in sorted(list(new_in_1)):
                print(f"  - {domain}")
        if removed_in_2:
            print("\nRemoved domains:")
            for domain in sorted(list(removed_in_2)):
                print(f"  - {domain}")

# ---------------------------
# Main runnable
# ---------------------------
def main():
    global interrupted
    
    # Register signal handlers for graceful interruption
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(description="Generate and maintain phishing feeds for Australian entities")
    parser.add_argument("--start", action="store_true", help="Generate Australian phishing feeds")
    parser.add_argument("--reclassify-feeds", action="store_true", help="Reclassify existing feed files without fetching remote sources")
    parser.add_argument("--compare-feeds", type=str, nargs='*', help="Compare feeds between two dates (YYYY-MM-DD) or latest and previous. Usage: --compare-feeds [DATE1] [DATE2]")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    if args.reclassify_feeds:
        reclassify_existing_feeds()
        return

    if args.compare_feeds is not None:
        if len(args.compare_feeds) == 2:
            date1_str = args.compare_feeds[0]
            date2_str = args.compare_feeds[1]
            compare_feed_runs(date1_str, date2_str)
        elif len(args.compare_feeds) == 0:
            compare_feed_runs() # Compare latest with previous archived
        else:
            print("❌ Invalid usage of --compare-feeds. Please provide 0 or 2 dates (YYYY-MM-DD).")
        return

    # Initialize sets for Australian categories
    if args.start:
        processed_hosts, remaining_hosts, banking, government, utilities, rejected = load_checkpoint()
    else:
        # Default: generate Australian feeds
        processed_hosts, remaining_hosts, banking, government, utilities, rejected = load_checkpoint()
    
    if processed_hosts is not None and remaining_hosts is not None:
        print(f"🔄 Resuming processing with {len(remaining_hosts)} hosts remaining...")
        hosts = remaining_hosts
        # We're resuming, so we don't need to fetch again
        # But we still need to get the feed counts for display
        feed_counts = {"Resumed from checkpoint": len(processed_hosts) + len(remaining_hosts)}
    else:
        processed_hosts = set()
        banking, government, utilities = set(), set(), set()
        rejected = []
        
        if DEBUG_REJECTIONS:
            try:
                open(REJECTIONS_LOG, "w", encoding="utf-8").close()
            except Exception:
                pass

        # Fetch all feeds in parallel for performance
        raw, feed_counts = fetch_all_feeds_parallel()

        # Fetch URLScan feed and add domains to raw entries
        urlscan_domains = fetch_urlscan()
        raw.extend(urlscan_domains)
        feed_counts["URLScan"] = len(urlscan_domains)

        print(f"📊 Total raw entries: {len(raw)}")

        hosts = {normalize_host(x) for x in raw if x and x.strip()}
        hosts = {h for h in hosts if h and not h.startswith('0.0.0.0 ')}
        hosts = {h for h in hosts if is_valid_host(h)}
        print(f"📊 Normalized unique hosts: {len(hosts)}")

    total_hosts = len(processed_hosts) + len(hosts)
    print(f"📊 Total hosts to process: {total_hosts}")
    print(f"📊 Already processed: {len(processed_hosts)}")

    # Use multiprocessing to speed up classification
    num_workers = max(1, min(multiprocessing.cpu_count(), 8))
    print(f"🚀 Using {num_workers} workers for parallel classification...")

    # Convert hosts to a list for deterministic ordering
    hosts_list = sorted(hosts)

    # Process in chunks for progress reporting and checkpointing
    CHUNK_SIZE = 5000
    all_results = []

    for chunk_start in range(0, len(hosts_list), CHUNK_SIZE):
        if interrupted:
            print(f"🛑 Processing interrupted at host {chunk_start+1}/{len(hosts_list)}")
            remaining_hosts = set(hosts_list[chunk_start:])
            save_checkpoint(processed_hosts, remaining_hosts, banking, government, utilities, rejected)
            return

        chunk = hosts_list[chunk_start:chunk_start + CHUNK_SIZE]

        # Process chunk in parallel
        with multiprocessing.Pool(processes=num_workers) as pool:
            chunk_results = pool.map(classify_host, chunk)

        # Process results
        for h, (cat, reason) in zip(chunk, chunk_results):
            all_results.append((h, cat, reason))
            if cat == "banking":
                banking.add(h)
            elif cat == "government":
                government.add(h)
            elif cat == "utilities":
                utilities.add(h)
            else:
                if DEBUG_REJECTIONS:
                    rejected.append((h, reason))
            processed_hosts.add(h)

        # Report progress
        # Update progress in place; use carriage return to overwrite the line
        print(f"\rProgress: {len(processed_hosts)}/{total_hosts} hosts processed...", end='', flush=True)

        # Save checkpoint every chunk
        remaining_hosts = set(hosts_list[chunk_start + CHUNK_SIZE:])
        save_checkpoint(processed_hosts, remaining_hosts, banking, government, utilities, rejected)

    print(f"🏦 Banking: {len(banking)}")
    print(f"🏛️ Government: {len(government)}")
    print(f"⚡ Utilities (incl. telecom): {len(utilities)}")
    print(f"🗑️ Rejected: {len(rejected)}")

    # Print per-feed entry counts
    print("\n📊 Entries per feed:")
    for url, count in sorted(feed_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   {url}: {count}")

    if DEBUG_REJECTIONS:
        try:
            with open(REJECTIONS_LOG, "w", encoding="utf-8") as rf:
                rf.write("host\treject_reason\n")
                for h, r in sorted(rejected):
                    rf.write(f"{h}\t{r}\n")
            print(f"📝 Wrote rejection reasons → {REJECTIONS_LOG}")
        except Exception as e:
            print(f"⚠️ Failed to write rejection log: {e}")

    today = datetime.now().strftime("%Y-%m-%d")
    archive_existing_feeds(exclude_filenames={os.path.basename(REJECTIONS_LOG)})

    files_out = {
        "banking": os.path.join(OUTPUT_DIR, f"australian_phish_banking_{today}.txt"),
        "government": os.path.join(OUTPUT_DIR, f"australian_phish_government_{today}.txt"),
        "utilities": os.path.join(OUTPUT_DIR, f"australian_phish_utilities_{today}.txt"),
    }

    category_sets = {"banking": banking, "government": government, "utilities": utilities}
    for name, path in files_out.items():
        cleaned = []
        for h in sorted(category_sets[name]):
            ext = get_cached_tld_extraction(h)  # Use cached extraction
            sfx = (ext.suffix or '').lower()
            if sfx == 'fr':
                continue
            cleaned.append(h)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(cleaned))
            print(f"✅ Saved {name} feed → {path}")
        except Exception as e:
            print(f"⚠️ Failed to save {name} feed → {e}")
    
    # Clean up checkpoint files after successful completion
    try:
        if os.path.exists(CHECKPOINT_FILE):
            os.remove(CHECKPOINT_FILE)
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)
        print("🧹 Cleaned up checkpoint files after successful completion")
    except Exception as e:
        print(f"⚠️ Failed to clean up checkpoint files: {e}")

if __name__ == "__main__":
    main()
