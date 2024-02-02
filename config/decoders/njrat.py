from config.interface import Decoder
import pype32
import logging
import config.utils as utils

logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class NjRat(Decoder):

    decoder_name = "njRat"
    decoder__version = 1
    decoder_author = ""
    decoder_description = "njRat decoder"
    decoder_active = True

    def __init__(self):

        self.conf = {}
        self.IOC_TARGETS = {
            'tags': ['Port', 'version'],
            'iocs': {
                'Domain': ""
            }
        }

    def config(self, file_path):
        try:
            pe = pype32.PE(file_path)
            sha1 = file_path.split('/')[-1]
            string_list = self.get_strings(pe, 2)
            return self.parse_config(string_list, sha1)
        except Exception as ex:
            logger.error(f'Unable to decode njRat file {file_path} : {ex}')
            return False

    def get_config(self):
        return self.conf

    # Helper Functions Go Here
    # Get a list of strings from a section
    def get_strings(self, pe, dir_type):
        string_list = []
        m = pe.ntHeaders.optionalHeader.dataDirectory
        m = pe.ntHeaders.optionalHeader.dataDirectory[14].info
        if m and hasattr(m, 'netMetaDataStreams'):
            for s in m.netMetaDataStreams[dir_type].info:
                for offset, value in s.items():
                    string_list.append(value)
        return string_list

    # Turn the strings in to a python dict
    def parse_config(self, string_list, sha1):
        config_dict = {"indicators": []}
        try:
            _0_6_4_index = string_list.index('0.6.4')
        except:
            _0_6_4_index = None
        if string_list[5] == '0.3.5':
            indicator = {}
            if string_list[7] and utils.is_domain(string_list[7]):
                indicator["type"] = "domain"
                indicator["value"] = string_list[7]
            if string_list[7] and utils.is_ip_address(string_list[7]):
                indicator["type"] = "ipv4"
                indicator["value"] = string_list[7]
            if indicator:
                config_dict["indicators"].append(indicator)
                config_dict["version"] = string_list[5]
                config_dict["install_name"] = string_list[1]
                config_dict["install_dir"] = string_list[2]
                config_dict["registry_value"] = string_list[3]
                config_dict["port"] = string_list[8]
                config_dict["network_separator"] = string_list[9]
                config_dict["install_flag"] = string_list[6]
            config_dict["regkey_for_persistance"] = ""
        elif string_list[6] == '0.3.6':
            indicator = {}
            if string_list[8] and utils.is_domain(string_list[8]):
                indicator["type"] = "domain"
                indicator["value"] = string_list[8]
            if string_list[8] and utils.is_ip_address(string_list[8]):
                indicator["type"] = "ipv4"
                indicator["value"] = string_list[8]
            if indicator:
                config_dict["indicators"].append(indicator)
                config_dict["version"] = string_list[6]
                config_dict["install_name"] = string_list[2]
                config_dict["install_dir"] = string_list[3]
                config_dict["registry_value"] = string_list[4]
                config_dict["port"] = string_list[9]
                config_dict["network_separator"] = string_list[10]
                config_dict["install_flag"] = string_list[11]
                config_dict["regkey_for_persistance"] = ""
        elif string_list[3] == '0.4.1a':
            indicator = {}
            if string_list[8] and utils.is_domain(string_list[8]):
                indicator["type"] = "domain"
                indicator["value"] = string_list[8]
            if string_list[8] and utils.is_ip_address(string_list[8]):
                indicator["type"] = "ipv4"
                indicator["value"] = string_list[8]
            if indicator:
                config_dict["indicators"].append(indicator)
                config_dict["version"] = string_list[3]
                config_dict["install_name"] = string_list[5]
                config_dict["install_dir"] = string_list[6]
                config_dict["registry_value"] = string_list[7]
                config_dict["port"] = string_list[9]
                config_dict["network_separator"] = string_list[10]
                config_dict["install_flag"] = string_list[11]
                config_dict["regkey_for_persistance"] = ""
        elif string_list[2] == '0.5.0E':
            indicator = {}
            if string_list[7] and utils.is_domain(string_list[7]):
                indicator["type"] = "domain"
                indicator["value"] = string_list[7]
            if string_list[7] and utils.is_ip_address(string_list[7]):
                indicator["type"] = "ipv4"
                indicator["value"] = string_list[7]
            if indicator:
                config_dict["indicators"].append(indicator)
                config_dict["version"] = string_list[2]
                config_dict["install_name"] = string_list[4]
                config_dict["install_dir"] = string_list[5]
                config_dict["registry_value"] = string_list[6]
                config_dict["port"] = string_list[8]
                config_dict["install_flag"] = string_list[9]
                config_dict["network_separator"] = string_list[10]
                config_dict["regkey_for_persistance"] = ""
        elif string_list[2] == '0.8d':
            indicator = {}
            if string_list[7] and utils.is_domain(string_list[7]):
                indicator["type"] = "domain"
                indicator["value"] = string_list[7]
            if string_list[7] and utils.is_ip_address(string_list[7]):
                indicator["type"] = "ipv4"
                indicator["value"] = string_list[7]
            if indicator:
                config_dict["indicators"].append(indicator)
                config_dict["version"] = string_list[2]
                config_dict["install_name"] = string_list[4]
                config_dict["install_dir"] = string_list[5]
                config_dict["registry_value"] = string_list[6]
                config_dict["port"] = string_list[8]
                config_dict["network_separator"] = string_list[10]
                config_dict["install_flag"] = string_list[9]
                config_dict["regkey_for_persistance"] = string_list[12]
        elif _0_6_4_index and string_list[_0_6_4_index] == '0.6.4':
            indicator = {}
            vIndex = _0_6_4_index
            if string_list[vIndex + 4] and utils.is_domain(string_list[vIndex + 4]):
                indicator["type"] = "domain"
                indicator["value"] = string_list[vIndex + 4]
            if string_list[vIndex + 4] and utils.is_ip_address(string_list[vIndex + 4]):
                indicator["type"] = "ipv4"
                indicator["value"] = string_list[vIndex + 4]
            if indicator:
                config_dict["indicators"].append(indicator)
                config_dict["version"] = string_list[vIndex]
                config_dict["install_name"] = string_list[vIndex + 1]
                config_dict["install_dir"] = string_list[vIndex + 2]
                config_dict["registry_value"] = string_list[vIndex + 3]
                config_dict["port"] = string_list[vIndex + 5]
                config_dict["network_separator"] = string_list[vIndex + 6]
                config_dict["install_flag"] = string_list[vIndex + 7]
                config_dict["regkey_for_persistance"] = ""
        elif string_list[2] == '0.7.1':
            indicator = {}
            if string_list[7] and utils.is_domain(string_list[7]):
                indicator["type"] = "domain"
                indicator["value"] = string_list[7]
            if string_list[7] and utils.is_ip_address(string_list[7]):
                indicator["type"] = "ipv4"
                indicator["value"] = string_list[7]
            if indicator:
                config_dict["indicators"].append(indicator)
                config_dict["version"] = string_list[2]
                config_dict["mutex"] = string_list[3]
                config_dict["install_name"] = string_list[4]
                config_dict["install_dir"] = string_list[5]
                config_dict["registry_value"] = string_list[6]
                config_dict["port"] = string_list[8]
                config_dict["network_separator"] = string_list[10]
                config_dict["install_flag"] = string_list[9]
                config_dict["author"] = string_list[12]
                config_dict["regkey_for_persistance"] = ""
        elif string_list[2] == '0.7d':
            indicator = {}
            if string_list[6] and utils.is_domain(string_list[6]):
                indicator["type"] = "domain"
                indicator["value"] = string_list[6]
            if string_list[6] and utils.is_ip_address(string_list[6]):
                indicator["type"] = "ipv4"
                indicator["value"] = string_list[6]
            if indicator:
                config_dict["indicators"].append(indicator)
                config_dict["version"] = string_list[2]
                config_dict["install_name"] = string_list[3]
                config_dict["install_dir"] = string_list[4]
                config_dict["registry_value"] = string_list[5]
                config_dict["port"] = string_list[7]
                config_dict["network_separator"] = string_list[8]
                config_dict["install_flag"] = string_list[9]
                config_dict["regKey_for_persistance"] = ""
        else:
            string_list = [e for e in string_list if e]
            logger.info(f"[{self.decoder_name}] Missed config version match. Attempting to search in {type(string_list)}")
            logger.info(f"{string_list}")
            version = None
            if "0.4.1a" in string_list:
                version = "0.4.1a"
            if "0.8d" in string_list:
                version = "0.8d"
            if "0.5.0E" in string_list:
                version = "0.5.0E"
            if "0.9" in string_list:
                version = "0.9"
            if version:
                version_index = string_list.index(version)
                indicator = string_list[version_index+4]
                indicator_dict = {}
                if indicator and utils.is_domain(indicator):
                    indicator_dict["type"] = "domain"
                    indicator_dict["value"] = indicator
                if indicator and utils.is_ip_address(indicator):
                    indicator_dict["type"] = "ipv4"
                    indicator_dict["value"] = indicator
                if indicator_dict:
                    config_dict["indicators"].append(indicator_dict)
                    config_dict["version"] = version
                    config_dict["install_name"] = string_list[version_index+1]
                    config_dict["install_dir"] = string_list[version_index+2]
                    config_dict["registry_value"] = string_list[version_index+3]
                    config_dict["port"] = string_list[version_index+5]
        if len(config_dict) > 0:
            self.conf = config_dict
        return self.conf
