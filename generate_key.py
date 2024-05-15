import datetime
import hashlib
import os
import secrets


BOUND: int = 1000
PIECES: int = 10000


def sha256_str(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: str) -> bytes:
    return hashlib.sha256(data.encode()).digest()


def xor_digest(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> None:
    numbers = [
        secrets.randbelow(BOUND)
        for _ in range(PIECES)
    ]

    secret = sha256_str(
        "".join(
            sha256_str(str(number).encode())
            for number in numbers
        ).encode()
    )

    recovery = []
    acc = None
    for number in numbers:
        number_hash = sha256_bytes(str(number))
        acc = xor_digest(acc, number_hash) if acc else number_hash
        recovery.append(sha256_str(acc))

    print(f"Secret key:\n{secret}\n")

    ts = datetime.datetime.utcnow().isoformat(timespec="minutes").replace(":", "-")
    secret_path = f"secret-{ts}.txt"
    recovery_path = f"recovery-{ts}.txt"

    if any(os.path.exists(path) for path in [secret_path, recovery_path]):
        raise RuntimeError("File exists")

    with open(secret_path, "w") as secret_f:
        secret_f.write(f"{secret}\n")

    print(f"Secret written to {secret_path}")

    with open(recovery_path, "w") as recovery_f:
        recovery_f.write("\n".join([f"{BOUND}"] + recovery + [""]))

    print(f"Recovery data written to {recovery_path}")


if __name__ == "__main__":
    main()
