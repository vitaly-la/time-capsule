import datetime
import hashlib
import os
import secrets
import sys

BOUND: int = 1000
PIECES: int = 10000


def sha256_str(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: str) -> bytes:
    return hashlib.sha256(data.encode()).digest()


def xor_digest(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def generate() -> None:
    salt = secrets.token_hex()

    numbers = [secrets.randbelow(BOUND) for _ in range(PIECES)]

    secret = sha256_str(
        "".join(sha256_str(f"{salt}{number}".encode()) for number in numbers).encode()
    )

    print(f"Secret key: {secret}")

    recovery = []
    acc = bytes(0 for _ in range(32))
    for number in numbers:
        number_hash = sha256_bytes(f"{salt}{number}")
        acc = xor_digest(acc, number_hash)
        recovery.append(sha256_str(acc))

    ts = datetime.datetime.utcnow().isoformat(timespec="minutes").replace(":", "-")
    secret_path = f"secret-{ts}.txt"
    recovery_path = f"recovery-{ts}.txt"

    if any(os.path.exists(path) for path in (secret_path, recovery_path)):
        raise RuntimeError("File exists")

    with open(secret_path, "w") as secret_f:
        secret_f.write(f"{secret}\n")

    print(f"Secret written to {secret_path}")

    with open(recovery_path, "w") as recovery_f:
        recovery_f.write("\n".join([str(salt), str(BOUND)] + recovery + [""]))

    print(f"Recovery data written to {recovery_path}")


def recover(recovery_path: str) -> None:
    with open(recovery_path, "r") as recovery_f:
        lines = [line.strip() for line in recovery_f.readlines()]

    salt = lines[0]
    bound = int(lines[1])

    number_hashes = []
    acc = bytes(0 for _ in range(32))
    recovered = 0
    percent = 0
    for lineno, line in enumerate(lines[2:]):
        for number in range(bound):
            number_hash = sha256_bytes(f"{salt}{number}")
            new_acc = xor_digest(acc, number_hash)

            if sha256_str(new_acc) == line:
                acc = new_acc
                number_hashes.append(sha256_str(f"{salt}{number}".encode()))

                recovered += 1
                new_percent = int(100 * recovered / (len(lines) - 2))
                if new_percent % 10 == 0 and new_percent > percent:
                    print(f"Recovered {new_percent}%")
                    percent = new_percent

                break

        if sha256_str(acc) != line:
            raise RuntimeError(f"Recovery file corrupted, line {lineno + 3}")

    secret = sha256_str("".join(number_hashes).encode())
    print(f"Secret key: {secret}")

    secret_path = recovery_path.replace("recovery", "secret")

    if os.path.exists(secret_path):
        raise RuntimeError("File exists")

    with open(secret_path, "w") as secret_f:
        secret_f.write(f"{secret}\n")

    print(f"Secret written to {secret_path}")


def usage() -> None:
    print("Usage: python3 time_capsule.py generate|recover <recovery file path>")


def main() -> None:
    try:
        match sys.argv[1]:
            case "generate":
                generate()
            case "recover":
                recovery_path = sys.argv[2]
                recover(recovery_path)
            case _:
                usage()
    except IndexError:
        usage()


if __name__ == "__main__":
    main()
