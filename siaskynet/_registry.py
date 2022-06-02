"""
"""


class RegistryEntry(object):

    def __init__(self, public_key: bytes, private_key: bytes,
                 prefix_endpoint_url: str = os.getenv('REGISTRY_URL', "https://siasky.net/"),
                 verbose=0,
                 ):
        """
        Args:
            private_key(bytes), public_key(bytes): These two keys are responsible to sign and verify the
            messages that will be sent and retreived from the skynet
        """

        self._pk = public_key
        self._sk = private_key
        if prefix_endpoint_url != "":
            self._endpoint_url = urljoin(prefix_endpoint_url, "skynet/registry")
        else:
            self._endpoint_url = urljoin("http://siasky.net/", "skynet/registry")

        # This below variable refers to max size of the signed message
        self._max_len = 64
        self._max_data_size = 113

        # Logger
        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(logging.NullHandler())
        self.logger.setLevel(logging.DEBUG)

        if verbose:
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
        self.logger.debug("Using endpoint url: " + self._endpoint_url)

    def set_entry(self, data_key: str, data: str, revision: int) -> bool:
        """
            - This function is based on the setEntry function of registry.ts.
            - Basically add an entry into the skynet with data_key as the key
        """
        # Make sure that the data size does not exceed the max bytes
        assert len(
            data) <= self._max_data_size, f"The data size({len(data)}) exceeded the limit of {self._max_data_size}."

        self.logger.debug("Inside set Entry function")

        # First sign the data
        hash_entry = hash_all((
            list(bytearray.fromhex(hash_data_key(data_key))),
            encode_string(data),
            encode_num(revision),
        ))
        raw_signed = nacl.bindings.crypto_sign(hash_entry, self._sk)

        # The public key needs to be encoded into a list of integers. Basically convert hex -> bytes
        public_key = {'algorithm': "ed25519", 'key': list(self._pk)}

        _data_key = hash_data_key(data_key)
        _data = list(data.encode())
        _signature = list(raw_signed)[:self._max_len]

        post_data = {
            'publickey': public_key,
            'datakey': _data_key,
            'revision': revision,
            'data': _data,
            'signature': _signature,
        }

        response = requests.post(self._endpoint_url, data=json.dumps(post_data))
        if response.status_code == 204:
            self.logger.debug("Data Successfully stored in the Registry")
        else:
            self.logger.debug(response.text)
            raise Exception("""
            The Registry Data was Invalid. Please do recheck that 
            - you are not using the same revision number to update the data. 
            - make sure that the keys used to sign the message come from the same seed value.
            """)

    def get_entry(self, data_key: str, timeout: int = 30) -> str:
        """
            - Get the entry given the dataKey
        """
        self.logger.debug("Inside get Entry function")
        self.logger.debug("Data Key:")
        self.logger.debug(data_key)
        self.logger.debug("Timeout:")
        self.logger.debug(data_key)
        self.logger.debug(timeout)
        publickey = f"ed25519:{self._pk.hex()}"
        datakey = hash_data_key(data_key)
        querry = {
            'publickey': publickey,
            'datakey': datakey,
        }
        # The below line will raise requests.exceptions.Timeout exception if it was unable to fetch the data
        # in two seconds.
        response = requests.get(self._endpoint_url, params=querry, timeout=timeout)
        self.logger.debug("Status Code: ")
        self.logger.debug(response.status_code)
        self.logger.debug("Status Text: ")
        self.logger.debug(response.text)
        response_data = json.loads(response.text)
        revision = response_data['revision']
        data = bytearray.fromhex(response_data['data']).decode()
        return (data, revision)

    async def aio_set_entry(self, data_key: str, data: str, revision: int):
        # Make sure that the data size does not exceed the max bytes
        assert len(
            data) <= self._max_data_size, f"The data size({len(data)}) exceeded the limit of {self._max_data_size}."

        self.logger.debug("Inside set Entry function")

        # First sign the data
        hash_entry = hash_all((
            list(bytearray.fromhex(hash_data_key(data_key))),
            encode_string(data),
            encode_num(revision),
        ))
        raw_signed = nacl.bindings.crypto_sign(hash_entry, self._sk)

        # The public key needs to be encoded into a list of integers. Basically convert hex -> bytes
        public_key = {'algorithm': "ed25519", 'key': list(self._pk)}

        _data_key = hash_data_key(data_key)
        _data = list(data.encode())
        _signature = list(raw_signed)[:self._max_len]

        post_data = {
            'publickey': public_key,
            'datakey': _data_key,
            'revision': revision,
            'data': _data,
            'signature': _signature,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(self._endpoint_url, data=json.dumps(post_data)) as response:
                if response.status == 204:
                    self.logger.debug("Data Successfully stored")
                else:
                    self.logger.debug(response.text())
                    raise Exception("""
                    The Registry Data was Invalid. Please do recheck that 
                    - you are not using the same revision number to update the data. 
                    - make sure that the keys used to sign the message come from the same seed value.
                    """)


    async def aio_get_entry(self, data_key: str, timeout: int = 30,) -> str:
        """
            - Used aio requests to get data from skydb
        """
        self.logger.debug("Inside async get Entry function")
        publickey = f"ed25519:{self._pk.hex()}"
        datakey = hash_data_key(data_key)
        querry = {
            'publickey': publickey,
            'datakey': datakey,
        }
        # The below line will raise requests.exceptions.Timeout exception if it was unable to fetch the data
        # in two seconds.

        async with aiohttp.ClientSession() as session:
            async with session.get(self._endpoint_url, params=querry) as response:
                json_text = await response.text()
                response_data = json.loads(json_text)
                revision = response_data['revision']
                data = bytearray.fromhex(response_data['data']).decode()
                return {data_key: [data, revision]}