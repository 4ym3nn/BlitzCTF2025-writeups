import numpy as np
import glob
from math import factorial

def is_printable_ascii(c):
    return 32 <= c <= 126

def decode_flag():
    files = sorted(glob.glob("f*.txt"), key=lambda fn: int(fn[1:-4]))
    chars = []

    for fn in files:
        data = np.loadtxt(fn)
        x, y = data[:, 0], data[:, 1]

        X = np.column_stack([x**i for i in range(9)])
        coeffs, *_ = np.linalg.lstsq(X, y, rcond=None)

        best_char = '?'
        best_error = float('inf')
        best_info = None

        for i, a in enumerate(coeffs):
            val = a * factorial(i)
            rounded = round(val)
            error = abs(val - rounded)

            if is_printable_ascii(rounded) and error < best_error:
                best_char = chr(rounded)
                best_error = error
                best_info = (i, a, val, rounded, error)

        if best_char == '?':
            print(f"\n[!] Could not determine char for {fn}")
            for i, a in enumerate(coeffs):
                val = a * factorial(i)
                rounded = round(val)
                error = abs(val - rounded)
                print(f"  a{i} = {a:.8f}, a{i} * {i}! = {val:.2f}, round = {rounded}, error = {error:.2e}")
        else:
            n, a, val, r, err = best_info
        chars.append(best_char)

    print("".join(chars))

if __name__ == "__main__":
    decode_flag()
