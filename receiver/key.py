from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

new_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

new_public_key = new_private_key.public_key()

with open("new_private.pem", "wb") as f:
    f.write(
        new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open("new_public.pem", "wb") as f:
    f.write(
        new_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Keys generated successfully")