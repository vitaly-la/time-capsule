import hashlib
import os
import sys


def sha256_str(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: str) -> bytes:
    return hashlib.sha256(data.encode()).digest()


def xor_digest(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> None:
    try:
        recovery_path = sys.argv[1]
    except IndexError:
        print("Usage: python3 recover.py <path to recovery file>")
        return

    with open(recovery_path, "r") as recovery_f:
        lines = recovery_f.readlines()

    bound = int(lines[0].strip())

    acc = None
    number_hashes = []
    recovered = 0
    percent = 0
    for line in lines[1:]:
        for number in range(bound):
            number_hash = sha256_bytes(str(number))
            new_acc = xor_digest(acc, number_hash) if acc else number_hash

            if sha256_str(new_acc) == line.strip():
                acc = new_acc
                number_hashes.append(sha256_str(str(number).encode()))

                recovered += 1
                new_percent = int(100 * recovered / (len(lines) - 1))
                if new_percent % 10 == 0 and new_percent > percent:
                    print(f"Recovered {new_percent}%")
                    percent = new_percent

                break

    secret = sha256_str("".join(number_hashes).encode())
    print(f"Secret key: {secret}\n")

    secret_path = recovery_path.replace("recovery", "secret")

    if os.path.exists(secret_path):
        raise RuntimeError("File exists")

    with open(secret_path, "w") as secret_f:
        secret_f.write(f"{secret}\n")

    print(f"Secret written to {secret_path}")


if __name__ == "__main__":
    main()
