import string


class Decoder(object):
    decoder_name = ""
    decoder_version = 1.1
    decoder_author = ""
    decoder_description = ""
    decoder_active = False
    file_info = object

    def set_file(self, file_info):
        self.file_info = file_info

    def get_config(self):
        pass

    def config(self, file_path):
        pass

def string_printable(line):
    this_line = str(line)
    new_line = ''
    for c in this_line:
        if c in string.printable:
            new_line += c
        else:
            new_line += '\\x' + c.encode("utf-8").hex()
    return new_line