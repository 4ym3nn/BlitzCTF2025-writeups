from pwn import remote, context
import re

context.log_level = 'debug'

MOD = 10**9 + 7
# Transition matrix for BlitzBots (including retention of parents)
# B_{n+1} = B_n + 3*Y_n + 2*R_n
# Y_{n+1} = 2*B_n + Y_n + 3*R_n
# R_{n+1} = 3*B_n + 2*Y_n + R_n
M = [
    [1, 3, 2],
    [2, 1, 3],
    [3, 2, 1],
]

def mat_mult(A, B, mod):
    """Multiply two 3×3 matrices under modulo."""
    return [[
        (A[i][0] * B[0][j] + A[i][1] * B[1][j] + A[i][2] * B[2][j]) % mod
        for j in range(3)
    ] for i in range(3)]


def mat_pow(matrix, exponent, mod):
    """Fast exponentiation of a 3×3 matrix under modulo."""
    result = [[1 if i == j else 0 for j in range(3)] for i in range(3)]
    base = matrix
    while exponent > 0:
        if exponent & 1:
            result = mat_mult(result, base, mod)
        base = mat_mult(base, base, mod)
        exponent >>= 1
    return result


def compute_populations(B0, Y0, R0, N):
    """Compute B_N, Y_N, R_N after N days."""
    if N == 0:
        return B0 % MOD, Y0 % MOD, R0 % MOD
    P = mat_pow(M, N, MOD)
    BN = (P[0][0]*B0 + P[0][1]*Y0 + P[0][2]*R0) % MOD
    YN = (P[1][0]*B0 + P[1][1]*Y0 + P[1][2]*R0) % MOD
    RN = (P[2][0]*B0 + P[2][1]*Y0 + P[2][2]*R0) % MOD
    return BN, YN, RN


def main():
    host, port = 'pwn.blitzhack.xyz', 1234
    conn = remote(host, port)
    int_line_pattern = re.compile(r"^\d+ \d+ \d+ \d+$")

    try:
        while True:
            line = conn.recvline(timeout=10)
            if not line:
                break
            text = line.decode().strip()

            # Final feedback checker
            if not int_line_pattern.match(text):
                print(text)
                break

            B0, Y0, R0, N = map(int, text.split())
            BN, YN, RN = compute_populations(B0, Y0, R0, N)
            conn.sendline(f"{BN} {YN} {RN}".encode())
    except EOFError:
        pass
    finally:
        conn.close()

if __name__ == '__main__':
    main()

