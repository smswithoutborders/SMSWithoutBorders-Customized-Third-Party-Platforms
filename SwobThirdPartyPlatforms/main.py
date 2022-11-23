import os
import importlib.util
import json
import logging

logger = logging.getLogger(__name__)

base_dir = os.path.dirname(__file__)
platforms_dir = [ f.path for f in os.scandir(base_dir) if f.is_dir() ]

available_platforms = []

for platform in platforms_dir:
    basename = os.path.basename(platform)

    info_filepath = os.path.join(platform, "info.json")
    methods_filepath = os.path.join(platform, "methods.py")
    logo_filepath = os.path.join(platform, "%s-icon.svg" % basename)
    execute_filepath = os.path.join(platform, "%s.py" % basename)

    if os.path.exists(info_filepath) and os.path.exists(methods_filepath) and os.path.exists(logo_filepath) and os.path.exists(execute_filepath):
        available_platforms.append(basename)

from SwobThirdPartyPlatforms.exceptions import PlatformDoesNotExist

class ImportPlatform:
    """
    """
    def __init__(self, platform_name:str) -> object:
        """
        """
        self.platform_name = platform_name.lower()
        self.methods = None
        self.exceptions = None
        self.execute = None
        self.info = None

        try:
            platform_path = self.__get_platform_path_from_platform_name(platform_name=self.platform_name)

            if not platform_path:
                error = "%s Platform not found" % self.platform_name
                raise PlatformDoesNotExist(error)
            else:   
                platform_methods_filepath = os.path.join(platform_path, "methods.py")
                spec = importlib.util.spec_from_file_location(self.platform_name, platform_methods_filepath)   
                platform_methods = importlib.util.module_from_spec(spec)       
                spec.loader.exec_module(platform_methods)
                self.methods = platform_methods.Methods
                self.exceptions = platform_methods.exceptions
                
                platform_execute_filepath = os.path.join(platform_path, "%s.py" % self.platform_name)
                spec = importlib.util.spec_from_file_location(self.platform_name, platform_execute_filepath)   
                platform_execute = importlib.util.module_from_spec(spec)       
                spec.loader.exec_module(platform_execute)
                self.execute = platform_execute.execute

                platform_info_filepath = os.path.join(platform_path, "info.json")
                if os.path.exists(platform_info_filepath):
                    with open(platform_info_filepath, encoding="utf-8") as data_file:    
                        data = json.load(data_file)
                    self.info = data
                            
        except Exception as error:
            logger.error("Error importing platform '%s'" % self.platform_name)
            raise error

    def __get_platform_path_from_platform_name(self, platform_name:str) -> str:
        """
        """
        for Platform in available_platforms:
            if platform_name == Platform:
                platform_path = os.path.join(base_dir, Platform)
                return str(platform_path)

            else:
                continue

        return None
