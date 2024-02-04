from pathlib import Path

from rich.console import Console
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import typer
from typing_extensions import Annotated

from certman.enums import KeyType
from certman.p12 import P12File

app = typer.Typer()


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
        while not p12file.read(password.encode()):
            password = console.input(f"Password for {file.name}: ", password=True)
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
        password = ""
        while not p12file.read(password.encode()):
            password = console.input(f"Password for {file.name}: ", password=True)

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
