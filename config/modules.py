import importlib
import inspect
import pkgutil
import logging
from config import Decoder
from config import decoders

logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def load_decoders():

    dec_modules = dict()

    # Walk recursively through all modules and packages.
    for loader, module_name, ispkg in pkgutil.walk_packages(decoders.__path__, decoders.__name__ + '.'):
        # If current item is a package, skip.
        if ispkg:
            continue
        # Try to import the module, otherwise skip.
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            print("Unable to import Module {0}: {1}".format(module_name, e))
            continue
        for mod_name, mod_object in inspect.getmembers(module):
            if inspect.isclass(mod_object):
                if issubclass(mod_object, Decoder) and mod_object is not Decoder:
                    decoder_name = mod_object.decoder_name.lower()
                    if not mod_object.decoder_active:
                        logger.info(f"Decoder Set Inactive: {decoder_name}")
                        continue
                    logger.info(f"Loading Module: {decoder_name}.")
                    dec_modules[decoder_name] = dict(obj=mod_object,
                                                                decoder_name=decoder_name,
                                                                decoder_description=mod_object.decoder_description,
                                                                decoder_version=mod_object.decoder_version,
                                                                decoder_author=mod_object.decoder_author
                                                                )
                else:
                    logger.debug(f"IGNORING {mod_name} is not subclass of {Decoder}")
    return dec_modules


__decoders__ = load_decoders()