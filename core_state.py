# core_state.py
import threading

# =====================
# LOGGING / RUNTIME
# =====================

LOGS = []
MAX_LOGS = 100
LOG_PATH = ""

VERBOSE_LEVEL = 0



# =====================
# RUN MODULES
# =====================

RUN_PATHS = {}
MAX_RUNS = 100
RUN_PAYLOADS = {
    "xml": {
        "file": "simplexml.xml",
        "content_type": "application/xml",
    },
    "xxe1": {
        "file": "xxe01.xml",
        "content_type": "application/xml",
    },
    "xxe2": {
        "file": "xxe02.xml",
        "content_type": "application/xml",
    },
    "csv": {
        "file": "simplecsv.csv",
        "content_type": "text/csv",
    },
    "csvxss": {
        "file": "csvxss.csv",
        "content_type": "text/csv",
    },
    "csvrce": {
        "file": "csvrce.csv",
        "content_type": "text/csv",
    },
    "jpg": {
        "file": "simple.jpg",
        "content_type": "image/jpeg",
    },
    "jpgpixelflood": {
        "file": "jpgpixelflood.jpg",
        "content_type": "image/jpeg",
    },
    "png": {
        "file": "simple.png",
        "content_type": "image/png",
    },
    "svgbomb": {
        "file": "svgbomb.svg",
        "content_type": "image/svg+xml",
    },
}


# =====================
# FILES / DIRECTORIES
# =====================


TEMPLATE_DIR = "tools"
HOSTED_PREFIX = "hostedfiles"
HEADER_LOG_PATH = "header_capture.log"

# =====================
# COLORS
# =====================

C = {
    "RESET": "\033[0m",
    "YELLOW": "\033[93m",
    "GREEN": "\033[92m",
    "BLUE": "\033[94m",
    "RED": "\033[91m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m"
}

# =====================
# SERVERS
# =====================

ACTIVE_SERVERS = {}

# =====================
# GEOIP
# =====================

GEOIP_CACHE = {}
GEOIP_READER = None
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

# =====================
# PERSISTENCE
# =====================

PERSIST_PATH = None
PERSIST_LOCK = threading.Lock()

# =====================
# HOSTED FILES
# =====================

HOSTED_FILES = {}
HOSTED_LOCK = threading.Lock()

# =====================
# REDIRECTS
# =====================

REDIRECTS = {}
REDIRECT_LOCK = threading.Lock()
MAX_REDIRECTS = 100
REDIRECT_PREFIX = "redirect"

# =====================
# WHOIS
# =====================

WHOIS_CACHE = {}
WHOIS_LOCK = threading.Lock()
WHOIS_TTL = 24 * 3600
WHOIS_TIMEOUT = 6

# =====================
# REQUEST LIMITS
# =====================

MAX_BODY_BYTES = 20971520

# =====================
# DNS LISTENER (UDP)
# =====================

DNS_CONFIG = {
    "listen_ip": "0.0.0.0",
    "listen_port": 53,                 # DNS PORT
    "mode": "A",                       # "A" o "NXDOMAIN"
    "reply_ip": "IP",     # IP del VPS
    "domain_base": "introspector.sh", # ej: "xx.domain.com"
    "log_file": "dns_queries.log",
    "seen_file": "tokens_seen.json"
}

DNS_SERVER = {
    "running": False,
    "thread": None,
    "sock": None,
    "error": None,
}

DNS_SEEN_LOCK = threading.Lock()

# =====================
# DNS EXCEPTION TOKEN
# =====================

DNS_EXCEPTION_TOKEN = ""
DNS_EXAMPLE_TOKEN = ""

# =====================
# RESPONSE DESIGNER
# =====================

RESPONSE_DESIGNER_PATHS = {}
RESPONSE_DESIGNER_LOCK = threading.Lock()
MAX_RESPONSE_DESIGNER = 100

# =====================
# SCAN MODULES
# =====================

SCAN_MODULES = {
    "follow-redirect": {"enabled": False},
    "delayer": {"enabled": False},
}
