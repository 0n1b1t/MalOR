import ipaddress
import json
import requests
import logging
import validators
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from Crypto.Cipher import Blowfish
import traceback
import re

logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def is_ip_address(value):
    if value and isinstance(value, str):
        return validators.ipv4(value) #and not is_private_ip(value)
    return False

def is_ipv6_address(value):
    if value and isinstance(value, str):
        return validators.ipv6(value)
    return False

def is_domain(value):
    if value and isinstance(value, str):
        return re.match("((?!/)(?=[a-z0-9-]{1,63}\.)(xn\-\-)?[a-z0-9]+(-[a-z0-9]+)*\.)+(?!exe|shell|bin|cmd|bat|ini|bin|msi|js)[a-z]{2,63}", value)
    return False

def is_url(value):
    if value and isinstance(value, str):
        return re.search("^(?:(?:(?:https?):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z0-9\x00\xa1-\xff\xff][a-z0-9\x00\xa1}-\xff\xff}_-]{0,62})?[a-z0-9\x00\xa1-\xff\xff]\.)+(?:[a-z\x00\xa1-\xff\xff]{2,}\.?))(?::\d{2,5})?(?:[/?#]\S*)?$", value)
    return False

def is_private_ip(ip_address):
    if isinstance(ip_address, str):
        return ipaddress.ip_address(ip_address).is_private
    return False

def get_key():
    return chr(88)+'1'+ chr(82)+chr(83)+chr(86)+chr(70)+chr(73)+chr(119)+chr(89)+'2'+ chr(115)+chr(107)+chr(73)+chr(86)+'8'+chr(75)

def decrypt_text(key, text):
    try:
        c_obj = Blowfish.new(key, Blowfish.MODE_ECB)
        decrypted_pass = c_obj.decrypt(text)
        padding_size = ord(decrypted_pass[-1])
        passwd = decrypted_pass[:-padding_size]
        return str(passwd)
    except Exception as e:
        return

import datetime, logging
from collections import namedtuple
import re

BYTE_FOR_CHAR = list(map(chr, range(0,128)))
# These are lookup arrays used for quick checks on byte type
# TODO: Use bitarray instead of arrays of bools
DIGIT_CHARS = list(map(lambda x: x >= '0' and x <= '9', BYTE_FOR_CHAR))
ALPHA_CHARS = list(map(lambda x: x >= 'a' and x <= 'z' or x >= 'A' and x <= 'Z', BYTE_FOR_CHAR))
ALPHA_NUM_CHARS = list(map(lambda x: DIGIT_CHARS[ord(x)] or ALPHA_CHARS[ord(x)], BYTE_FOR_CHAR))
IPV4_CHARS = list(map(lambda x: DIGIT_CHARS[ord(x)] or x == '.', BYTE_FOR_CHAR))
HEX_CHARS = list(map(lambda x: DIGIT_CHARS[ord(x)] or x in "abcdefABCDEF", BYTE_FOR_CHAR))
IPV6_CHARS = list(map(lambda x: HEX_CHARS[ord(x)] or x == ':', BYTE_FOR_CHAR))
DOMAIN_CHARS = list(map(lambda x: IPV4_CHARS[ord(x)] or ALPHA_CHARS[ord(x)] or x in '-', BYTE_FOR_CHAR))
EMAIL_CHARS = list(map(lambda x: DOMAIN_CHARS[ord(x)] or x in '@!#$%&\'*+=?^_`{|}~', BYTE_FOR_CHAR))
URL_CHARS = list(map(lambda x: EMAIL_CHARS[ord(x)] or x in ':/[](),;', BYTE_FOR_CHAR))
EMAIL_DELIMITERS = list(map(lambda x: x in '[](),;', BYTE_FOR_CHAR))
COMMON_DELIMITERS = list(map(lambda x: EMAIL_DELIMITERS[ord(x)] or x in '{}|\'`', BYTE_FOR_CHAR))
TRIM_CHARS = list(map(lambda x: COMMON_DELIMITERS[ord(x)] or x in '.', BYTE_FOR_CHAR))

# States
IN_DIGIT=0
IN_IPV4=1
IN_HEX=2
IN_IPV6=3
IN_DOMAIN=4
IN_EMAIL=5
IN_URL=6
OUTSIDE=1000

# Delimiters specific to state
DELIMITERS_FOR_STATE = {
    IN_DIGIT: COMMON_DELIMITERS,
    IN_IPV4: COMMON_DELIMITERS,
    IN_HEX: COMMON_DELIMITERS,
    IN_IPV6: COMMON_DELIMITERS,
    IN_DOMAIN: COMMON_DELIMITERS,
    IN_EMAIL: EMAIL_DELIMITERS,
    IN_URL: list(map(lambda x: not URL_CHARS[ord(x)], BYTE_FOR_CHAR)),
}

# State->Type map
TYPES = {IN_HEX: 'md5', IN_IPV4: 'ipv4', IN_IPV6: 'ipv6', IN_DOMAIN: 'domain', IN_EMAIL: 'email', IN_URL: 'url'}

# Some lightweight records
TokenMeta = namedtuple('TokenMeta', ['index_start', 'index_end', 'state', 'counts'])

def is_trim(byte): return byte > 127 or TRIM_CHARS[byte]

class Extractor:

    def __init__(self, encoding='utf-8'):
        self.encoding = encoding
        self.initialize()

    def initialize(self):
        #         print 'initializing'
        self.tokens = {token_type: set() for token_type in TYPES.values()}
        self.index_start = 0
        self.index_end = 1
        self.initialize_token()

    def initialize_token(self):
        #         print 'initializing token'
        self.index_start = self.index_end - 1
        self.counts = [0] * 128
        self.state = OUTSIDE

    def tokenize(self, string):
        ''' This is the external facing method '''
        #         print 'Extracting from %s' % string

        # Extract byte array from string
        if isinstance(string, str):
            string = string.encode(self.encoding)
        return self.tokenize_bytes(bytearray(string))

    def tokenize_bytes(self, byte_sequence):
        ''' Tokenize a byte sequence '''

        # First some helper methods
        def examine_byte(index, byte):
            ''' State machine '''
            self.index_end = index
            if byte < 128: self.counts[byte] += 1
            byte_state = get_least_general_state_for_byte(byte)
            #             print 'examining %d:%s, byte_state %s, state = %s' % (index, chr(byte), TYPES.get(byte_state), TYPES.get(self.state))

            # Token Start
            if self.state == OUTSIDE:
                if not byte_state == OUTSIDE:
                    self.index_start = index
                    self.state = byte_state
                return

            # Token end
            if byte_state == OUTSIDE:
                append_token()
                return

            # Neither. just update state
            # First some 'special cases'
            if self.state == IN_DOMAIN and byte == ord(':'): byte_state = IN_URL
            if self.state == IN_HEX and byte == ord('.'): byte_state = IN_DOMAIN
            # The update current state if required
            self.state = max(self.state, byte_state)
        # Done examine_byte


        def flush(index):
            ''' Called when tokenize has reached the end of the array '''
            #             print 'flush'
            if not self.state == OUTSIDE:
                self.index_end = index + 1
                append_token()
        # Done flush

        def get_least_general_state_for_byte(byte):
            ''' Given a byte, what is the least general state we could be in? '''
            delims_for_state = DELIMITERS_FOR_STATE.get(self.state)
            if byte > 127 or delims_for_state and delims_for_state[byte]: return OUTSIDE # We don't handle high bytes
            if DIGIT_CHARS[byte]: return IN_DIGIT
            if HEX_CHARS[byte]: return IN_HEX
            if IPV4_CHARS[byte]: return IN_IPV4
            if IPV6_CHARS[byte]: return IN_IPV6
            if DOMAIN_CHARS[byte]: return IN_DOMAIN
            if EMAIL_CHARS[byte]: return IN_EMAIL
            if URL_CHARS[byte]: return IN_URL
            return OUTSIDE
        # Done get_least_general_state_for_byte

        def check_valid_token(type, value):
            if type == "ipv4":
                return is_ip_address(value)
            elif type == "md5":
                return validators.md5(value)
            elif type == "domain":
                return is_domain(value)
            elif type == "email":
                return validators.email(value)
            elif type == "url":
                return validators.url(value)
            elif type == "ipv6":
                return validators.ipv6(value)
            else:
                return False

        def append_token():
            ''' Append token metadata to list and initialize self '''
            # Trim the end, this has to be done here because it's also called from flush
            while self.index_start < min(len(byte_sequence), self.index_end) and is_trim(byte_sequence[self.index_start]):
                self.counts[byte_sequence[self.index_start]] -= 1
                self.index_start += 1
            #                 print 'trimming start %d' % self.index_end
            while self.index_end >= max(0, self.index_start) and is_trim(byte_sequence[self.index_end - 1]):
                self.counts[byte_sequence[self.index_end - 1]] -= 1
                self.index_end -= 1
            #                 print 'trimming end %d' % self.index_end

            token_meta = TokenMeta(self.index_start, self.index_end, self.state, self.counts)
            #                 print 'appending %s' % str(token_meta)
            if valid_meta(token_meta):
                token = byte_sequence[token_meta.index_start: token_meta.index_end].decode(self.encoding)
                #                if valid_token(token, token_meta.state):
                state_name = TYPES.get(token_meta.state)
                # TYPES = {IN_HEX: 'md5', IN_IPV4: 'ipv4', IN_IPV6: 'ipv6', IN_DOMAIN: 'domain', IN_EMAIL: 'email', IN_URL: 'url'}
                if check_valid_token(state_name, token.lower()):
                    self.tokens[state_name].add(token)
            self.initialize_token()
        # Done append_token

        def valid_meta(token_meta):
            ''' Is token valid? Uses just metadata '''
            def count(char): return token_meta.counts[ord(char)]
            length = token_meta.index_end - token_meta.index_start
            # TODO: We can speed this up further by putting the state -> validator in a dict
            if length < 2: valid = False
            elif token_meta.state == IN_DIGIT: valid = False
            elif token_meta.state == IN_IPV4: valid = length >= 7 and length <= 15 and count('.') == 3
            elif token_meta.state == IN_HEX: valid = length == 32
            elif token_meta.state == IN_IPV6: valid = length <= 39 and count(':') and count('.') == 0
            elif token_meta.state == IN_DOMAIN: valid = length >= 4 and count('.') >= 1
            elif token_meta.state == IN_EMAIL: valid = length >= 6 and count('.') >= 1 and count('@') == 1
            elif token_meta.state == IN_URL: valid = length >= 9 and count(':') >= 1 and count('/') >= 2
            #             print 'validating %s, type = %s, valid = %s' % (byte_sequence[token_meta.index_start : token_meta.index_end].decode(self.encoding), token_meta.state, valid)
            return valid
        # Done valid_meta

        #         def valid_token(token, state):
        #             ''' For those rare cases where we have to examine the actual token string to determine its validity'''
        #             return True
        #         # Done valid_token

        # body
        start = datetime.datetime.utcnow()  # @UndefinedVariable
        self.initialize()

        index = None
        for index, byte in enumerate(byte_sequence):
            examine_byte(index, byte)
        if index:
            flush(index)
        logging.info('Parse took %s' % (datetime.datetime.utcnow() - start))  # @UndefinedVariable
        return self.tokens

# TODO: extract this whole file out as its own lib (this is from optic)
def extract_patterns_from_normalized_text(content):
    """Given content, extract all the ip/url/domain/email patterns."""
    content = re.sub(r'\[(\.|dot)\]', '.', content, flags=re.IGNORECASE)
    content = re.sub(r'\<(\.|dot)\>', '.', content, flags=re.IGNORECASE)
    content = re.sub(r'h[.x()\[\]]{2,4}p://', 'http://', content, flags=re.IGNORECASE)
    content = re.sub(r'h[.x()\[\]]{2,4}ps://', 'https://', content, flags=re.IGNORECASE)
    content = re.sub(r'meow://', 'http://', content, flags=re.IGNORECASE)
    content = re.sub(r'me0w://', 'http://', content, flags=re.IGNORECASE)
    content = re.sub(r'purr://', 'http://', content, flags=re.IGNORECASE)
    content = re.sub(r'&amp;', '&', content, flags=re.IGNORECASE)

    found = Extractor().tokenize(content)
    #found['url'] = set(url[0:350] for url in found['url']) # Trim URLs to max db column length.
    #found['domain'] = set(domain[0:200] for domain in found['domain']) # trimming
    return found

class Controllers:

    logstash_url = "http://trt-logger.hq.fidelis:8080/"
    headers = {
        "content-type": "application/json",
        "user-agent": "Malor_1.0",
    }

    @classmethod
    def notify_elk(cls, msg):
        if isinstance(msg, dict):
            cls.headers["authorization"] = "Basic dHJ0LWxvZ3N0YXNoLXVzZXI6cHJlc2VydmUtZHVzdC1yZXdhcmQ="
            msg['tags'] = [
                "malor",
                "malware"
            ]
            data = json.dumps(msg)
            try:
                resp = requests.post(cls.logstash_url, headers=cls.headers, data=data, timeout=0.5)
                if resp.status_code == 200:
                    logger.debug(f"Stats sent to ELK. HTTP_CODE: {resp.status_code} - {resp.content}")
                    return True
                logging.debug(f"HTTP_CODE: {resp.status_code} - {resp.content}")
                return False
            except Exception as ex:
                logging.error(f"{ex}")
                return False


class SendEmail:

    def __init__(self, e_to=None, logger: logging.Logger = None):
        self.smtp_server = "smtp.office365.com"
        self.port = 587
        self.sender = "trt.notification@fidelissecurity.com"
        self.passwd = '\x96\x88\xf2o\x15\xc7\x03\xd3\xf1s\xf6r((#z'
        self.key = get_key()
        self.receiver = 'trtsystems@fidelissecurity.com' if not e_to else e_to
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)

    def send_email(self, content, err_type):
        try:
            server = smtplib.SMTP(self.smtp_server, self.port)
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender
            msg['To'] = self.receiver
            msg['subject'] = "[TRT] MalOR Notifucations - {}".format(err_type)
            part1 = MIMEText(content, "html")
            msg.attach(part1)
            server.ehlo()  # Can be omitted
            server.starttls()  # Secure the connection
            server.login(self.sender, decrypt_text(self.key, self.passwd))
            server.sendmail(self.sender, self.receiver, msg.as_string())
            server.quit()
        except Exception as ex:
            txt_fmt = traceback.format_exc()
            logging.error("{}: {}".format(__name__, txt_fmt))
            return
