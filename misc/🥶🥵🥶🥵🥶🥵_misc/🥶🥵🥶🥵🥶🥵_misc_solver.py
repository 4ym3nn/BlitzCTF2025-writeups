# collecting 10 pairs of input output to find the pattern

# from pwn import *
# import random
# import json

# context.log_level = 'error'

# host = 'pwn.blitzhack.xyz'
# port = 6789

# results = set()  # Track unique inputs
# pairs = []

# def make_random_input():
#     while True:
#         positions = random.sample(range(28), 14)
#         s = ['🧊'] * 28
#         for i in positions:
#             s[i] = '🔥'
#         result = ''.join(s)
#         if result not in results:
#             results.add(result)
#             return result

# def connect():
#     io = remote(host, port)
#     io.recvuntil(b'GIVE INPUT!!!')
#     return io

# io = connect()

# while len(pairs) < 10:
#     s = make_random_input()

#     try:
#         io.sendline(s.encode('utf-8'))
#         out = io.recvuntil(b'GIVE INPUT!!!', timeout=2).decode(errors='ignore')
#         cleaned = out.replace("TAKE OUTPUT!!!", "").replace("GIVE INPUT!!!", "").strip()

#         pairs.append({
#             "input": s,
#             "output": cleaned
#         })

#         print(f"[+] {len(pairs):02d}/10 collected")

#     except (EOFError, Exception) as e:
#         print("[!] Lost connection. Reconnecting...")
#         try: io.close()
#         except: pass
#         io = connect()

# try: io.close()
# except: pass

# with open("emoji_pairs.json", "w", encoding="utf-8") as f:
#     json.dump(pairs, f, indent=2, ensure_ascii=False)

# print("[*] Done! Saved 10 emoji pairs to emoji_pairs.json")



# Part 2: This was used to find the pattern and transformation used to transform the flag
# import json

# with open("emoji_pairs.json", encoding="utf-8") as f:
#     data = json.load(f)

# n = 28
# mapping_counts = [{} for _ in range(n)]

# for pair in data:
#     input_seq = pair['input']
#     output_seq = pair['output']
#     for i, out_emoji in enumerate(output_seq):
#         for j, in_emoji in enumerate(input_seq):
#             if out_emoji == in_emoji:
#                 mapping_counts[i][j] = mapping_counts[i].get(j, 0) + 1

# print("Likely output[i] = input[j] mappings (based on majority votes):\n")
# for i, count_dict in enumerate(mapping_counts):
#     if count_dict:
#         likely_j = max(count_dict, key=count_dict.get)
#         print(f"  output[{i}] ← input[{likely_j}]  ({count_dict[likely_j]} votes)")
#     else:
#         print(f"  output[{i}] ← ???")


# Part 3: After finding the transformation: getting the flag
transformed_flag = "32i3t{3!!_XB2M7!zlUM34727}P3"

forward = [
    11, 8, 2, 14, 3, 5, 17, 25, 26, 12,
    6, 0, 22, 15, 13, 24, 4, 1, 21, 10,
    23, 19, 20, 18, 7, 27, 16, 9
]

inverse = [None] * 28
for out_idx, in_idx in enumerate(forward):
    inverse[in_idx] = out_idx

flag = ''.join(transformed_flag[i] for i in inverse)
print(flag)
