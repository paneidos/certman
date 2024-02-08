from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, NamedTuple

from cryptography.hazmat._oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives._serialization import PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    CertificateBuilder,
    NameAttribute,
    Name,
    random_serial_number,
    BasicConstraints,
    ExtendedKeyUsage,
    KeyUsage,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    SubjectAlternativeName,
    DNSName,
    CRLDistributionPoints,
    DistributionPoint,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import NameOID, ObjectIdentifier
from rich.console import Console
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import typer
from typing_extensions import Annotated

from certman.enums import KeyType
from certman.p12 import P12File

app = typer.Typer()
export_app = typer.Typer()
app.add_typer(export_app, name="export")


def get_password(console: Console, p12file: P12File) -> str:
    password = ""
    while not p12file.read(password.encode()):
        password = console.input(f"Password for {p12file.name}: ", password=True)
    return password


@app.command()
def create(
    file: Annotated[Path, typer.Argument(help="The p12 file to read", mode="r+")],
    key_type: Annotated[
        KeyType, typer.Option(help="The type of key to use")
    ] = KeyType.RSA.value,
):
    console = Console()

    p12file = P12File(file)
    password = None
    if p12file.exists():
        password = ""
        password = get_password(console, p12file)
        if p12file.key is not None:
            answer = console.input(
                "File already contains a private key, overwrite? (y/N) "
            )
            if answer == "" or answer[0].lower() != "y":
                raise typer.Abort()

    match key_type:
        case KeyType.RSA:
            p12file.key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
        case KeyType.ECDSA:
            p12file.key = ec.generate_private_key(ec.SECP384R1())

    while password is None:
        password = console.input(f"New password: ", password=True)
        confirm_password = console.input(f"Confirm password: ", password=True)
        if password != confirm_password:
            console.print("[red]Passwords do not match[/red]")
            continue
        elif len(password) < 4 and len(password) != 0:
            console.print("[red]Password too short[/red]")
            continue

    p12file.write(password.encode())


@app.command()
def info(file: Annotated[Path, typer.Argument(help="The p12 file to read")]):
    console = Console()

    p12file = P12File(file)
    if p12file.exists():
        password = get_password(console, p12file)

    if p12file.key is not None:
        match p12file.key:
            case rsa.RSAPrivateKey():
                key_type = "RSA"
                key: rsa.RSAPrivateKey = p12file.key
                key_data = f"(size={key.key_size})"
            case ec.EllipticCurvePrivateKey():
                key_type = "ECDSA"
                key: ec.EllipticCurvePrivateKey = p12file.key
                key_data = f"(curve={key.curve.name}, size={key.key_size})"
            case _:
                key_type = "Unknown"
                key_data = ""
        console.print(f"Private key: {key_type}{key_data}")


class CertificateAttribute(NamedTuple):
    key: str
    label: str
    oid: ObjectIdentifier
    example: str
    multiple: bool
    ask: bool


CERTIFICATE_ATTRIBUTES = [
    CertificateAttribute("country", "Country", NameOID.COUNTRY_NAME, "NL", False, True),
    CertificateAttribute(
        "state",
        "State/Province",
        NameOID.STATE_OR_PROVINCE_NAME,
        "Noord-Holland",
        False,
        True,
    ),
    CertificateAttribute(
        "city", "City/Locality", NameOID.LOCALITY_NAME, "Amsterdam", False, True
    ),
    CertificateAttribute(
        "org",
        "Organization",
        NameOID.ORGANIZATION_NAME,
        "Example B.V.",
        False,
        True,
    ),
    CertificateAttribute(
        "ou", "OU", NameOID.ORGANIZATIONAL_UNIT_NAME, "IT", False, True
    ),
    CertificateAttribute(
        "cn", "Common Name", NameOID.COMMON_NAME, "Domain name", False, True
    ),
    CertificateAttribute(
        "email", "Email Address", NameOID.EMAIL_ADDRESS, "you@example.com", False, True
    ),
    CertificateAttribute(
        "unstructured", "Unstructured Name", NameOID.UNSTRUCTURED_NAME, "", False, False
    ),
]


def convert_attributes(attributes: list[str]) -> dict[CertificateAttribute, list[str]]:
    results = {}
    all_attributes = {attribute.key: attribute for attribute in CERTIFICATE_ATTRIBUTES}
    for attribute in attributes:
        key, value = attribute.split(":")
        if key not in all_attributes:
            raise typer.Abort(f"Unknown attribute: {key}")
        attr = all_attributes[key]
        if attr.multiple:
            current = results.get(attr, [])
            current.append(value)
            results[attr] = current
        else:
            results[attr] = value
    return results


def ask_attributes(console: Console) -> dict[CertificateAttribute, list[str]]:
    results = {}
    for attribute in CERTIFICATE_ATTRIBUTES:
        if not attribute.ask:
            continue

        if attribute.multiple:
            result_list = []
            while result := console.input(
                f"{attribute.label} (e.g. {attribute.example}): "
            ):
                result_list.append(result)
            if len(result_list) > 0:
                results[attribute] = result_list
        else:
            result = console.input(f"{attribute.label} (e.g. {attribute.example}): ")
            if result:
                results[attribute] = result
    return results


@app.command()
def sign(
    file: Annotated[Path, typer.Argument(help="The p12 file to read/write")],
    sign_with: Annotated[
        Optional[Path],
        typer.Argument(
            help="The p12 file to use as signing certificate, omit to self-sign",
        ),
    ] = None,
    expires: Annotated[
        Optional[int],
        typer.Option(metavar="days", help="Number of days before certificate expires"),
    ] = 365,
    attributes: Annotated[
        Optional[list[str]],
        typer.Option(
            metavar="attribute:value", help="Specify values for the certificate"
        ),
    ] = None,
    ca: Annotated[Optional[bool], typer.Option(help="Use as CA")] = False,
    crl: Annotated[
        Optional[list[str]],
        typer.Option(metavar="url", help="URL where CRL can be found"),
    ] = None,
    dns: Annotated[
        Optional[list[str]],
        typer.Option(
            metavar="domain", help="Specify the DNS names for the certificate"
        ),
    ] = None,
):
    console = Console()
    p12file = P12File(file)
    if not p12file.exists():
        raise typer.Abort("File not found")

    password = get_password(console, p12file)
    if p12file.certificate is not None:
        answer = console.input("File already contains a certificate, overwrite? (y/N) ")
        if answer == "" or answer[0].lower() != "y":
            raise typer.Abort()

    issuer_name = None
    issuer_key = p12file.key
    if sign_with is not None:
        sign_p12 = P12File(sign_with)
        get_password(console, sign_p12)
        issuer_key = sign_p12.key
        issuer_name = sign_p12.certificate.certificate.subject
        p12file.chain = [sign_p12.certificate]

    if attributes is None or len(attributes) == 0:
        sign_attributes = ask_attributes(console)
    else:
        sign_attributes = convert_attributes(attributes)

    name_attributes = [
        NameAttribute(attr.oid, value)
        for attr, value in sign_attributes.items()
        if isinstance(value, str)
    ]
    subject_name = Name(name_attributes)
    if issuer_name is None:
        issuer_name = subject_name

    cert_builder = (
        CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(p12file.key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=expires))
    )
    extensions = [
        ExtendedKeyUsage(
            [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
        ),
        SubjectKeyIdentifier.from_public_key(p12file.key.public_key()),
        AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
    ]
    critical_extensions = []
    alternate_names = []
    if dns is not None and len(dns) > 0:
        alternate_names += [DNSName(domain) for domain in dns]
    if len(alternate_names):
        extensions.append(SubjectAlternativeName(alternate_names))
    if ca:
        critical_extensions += [
            BasicConstraints(ca=True, path_length=None),
            KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
        ]
        if crl is not None and len(crl) > 0:
            extensions.append(
                CRLDistributionPoints(
                    [
                        DistributionPoint(full_name=UniformResourceIdentifier(url))
                        for url in crl
                    ]
                )
            )
    else:
        critical_extensions += [
            BasicConstraints(ca=False, path_length=None),
            KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
        ]
    for critical_extension in critical_extensions:
        cert_builder = cert_builder.add_extension(critical_extension, critical=True)
    for extension in extensions:
        cert_builder = cert_builder.add_extension(extension, critical=False)
    cert = cert_builder.sign(issuer_key, SHA256())
    p12file.certificate = cert
    p12file.write(password.encode())


@export_app.command("certificate")
def export_certificate(
    file: Annotated[Path, typer.Argument(help="The p12 file to read/write")],
    output: Annotated[
        Optional[Path], typer.Option(help="Where to write the certificate")
    ] = None,
):
    console = Console()

    p12file = P12File(file)
    password = get_password(console, p12file)

    if p12file.certificate is not None:
        data = p12file.certificate.certificate.public_bytes(Encoding.PEM)
        chain_data = [
            cert.certificate.public_bytes(Encoding.PEM)
            for cert in (p12file.chain or [])
        ]
        all_data = b"".join([data, *chain_data])
        if output is None:
            console.print(all_data.decode(), end="")
        else:
            output.write_bytes(all_data)


@export_app.command("key")
def export_key(
    file: Annotated[Path, typer.Argument(help="The p12 file to read/write")],
    output: Annotated[
        Optional[Path], typer.Option(help="Where to write the key")
    ] = None,
):
    console = Console()

    p12file = P12File(file)
    password = get_password(console, p12file)

    if p12file.key is not None:
        data = p12file.key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        if output is None:
            console.print(data.decode(), end="")
        else:
            output.write_bytes(data)
