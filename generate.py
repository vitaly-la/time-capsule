import datetime
import hashlib
import secrets
from base64 import b64encode

PIECES = 10
HASH_COUNT = 10


def main():
    initial_hashes = [secrets.token_bytes(32) for _ in range(PIECES)]

    final_hashes = []
    for hash in initial_hashes:
        for _ in range(HASH_COUNT):
            hash = hashlib.sha256(hash).digest()
        final_hashes.append(hash)

    secret = hashlib.sha256(b"".join(final_hashes)).hexdigest()
    print(f"Secret key: {secret}")

    recovery_data = [initial_hashes[0]]
    for initial_hash, final_hash in zip(initial_hashes[1:], final_hashes):
        secret_hash = bytes(x ^ y for x, y in zip(initial_hash, final_hash))
        recovery_data.append(secret_hash)

    ts = datetime.datetime.utcnow().isoformat(timespec="minutes").replace(":", "-")
    secret_path = f"secret-{ts}.txt"
    recovery_path = f"recovery-{ts}.txt"

    with open(secret_path, "w") as secret_f:
        secret_f.write(f"{secret}\n")
    print(f"Secret written to {secret_path}")

    with open(recovery_path, "w") as recovery_f:
        recovery_f.write(
            "\n".join(
                [str(HASH_COUNT)]
                + [b64encode(secret_hash).decode() for secret_hash in recovery_data]
                + [""]
            )
        )
    print(f"Recovery data written to {recovery_path}")


if __name__ == "__main__":
    main()
