from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    pkcs12,
    BestAvailableEncryption,
    NoEncryption,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12Certificate


class P12File:
    key: RSAPrivateKey | EllipticCurvePrivateKey | None
    certificate: PKCS12Certificate | None

    def __init__(self, path: Path):
        self.path = path
        self.key = None
        self.certificate = None
        self.chain = None
        self._loaded = False

    @property
    def name(self):
        return self.path.name

    def exists(self) -> bool:
        return self.path.exists()

    def read(self, password: bytes):
        if not self.exists():
            return False

        data = self.path.read_bytes()
        try:
            contents = pkcs12.load_pkcs12(data, password)
            self.key = contents.key
            self.certificate = contents.cert
            self.chain = contents.additional_certs
            self._loaded = True
            return True
        except ValueError:
            return False

    def write(self, password: bytes):
        data = pkcs12.serialize_key_and_certificates(
            name=None,
            key=self.key,
            cert=self.certificate,
            cas=self.chain,
            encryption_algorithm=BestAvailableEncryption(password)
            if len(password) > 0
            else NoEncryption(),
        )
        self.path.write_bytes(data)
