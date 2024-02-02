from pymongo import MongoClient
import logging


class MalorDB:

    def __init__(self, logger: logging.Logger = None):

        self.collection_name = "malor"
        self.mongo_database = "database"
        self.mongo_server = "mongo_server"
        self.mongo_user = "db_username"
        self.mongo_pass = "db_password"
        self.mongo_url = "mongodb://{2}:{3}@{0}/{1}".format(
            self.mongo_server,
            self.mongo_database,
            self.mongo_user,
            self.mongo_pass
        )
        self.mongo_client = MongoClient(host=self.mongo_url, document_class=dict)
        self.client_db = self.mongo_client[self.mongo_database]
        self.malor_collection = self.client_db[self.collection_name]
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)

    def close_connection(self):
        self.mongo_client.close()

    def get_mongo_collection(self, collection_name: str = None):
        if collection_name:
            return self.client_db[collection_name]
        return self.client_db[self.collection_name]

    def store_deocder_result(self, result: dict = None):
        if result and isinstance(result, dict):
            result = self.malor_collection.insert_one(result)
            return result
        return None
