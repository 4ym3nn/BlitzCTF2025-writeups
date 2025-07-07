from pwn import *


# wanted flag byte
wanted  = ""
with open("AA.enc", "rb") as f:
    wanted = f.read()
wanted = wanted.split(b"==")[1]

context.binary = './times_now'
env = {"LD_PRELOAD": os.path.abspath("fake_time.so")}


# collected flag
flag = b"Blitz{"


# brute force all bytes
for i in range(len(wanted)):
    for j in range(0,255):
        # open and write one byte
        with open("flag.txt","wb") as f:
            f.write(flag + bytes([j]))
        

        # run encryption script
        p = process(['./times_now'], env=env)
        p.wait_for_close()
        data_out = ""
        with open("flag.txt.enc", "rb") as f:
            data = f.read()
        data = data.split(b"==")[1]
        print(data.hex())
        print(wanted.hex())
        print(len(flag) + 1)


        # check if the byte is the same
        if data[len(flag) + 1] ==  wanted[len(flag) + 1]:
            print("Found",chr(j),data[len(flag) + 1],wanted[len(flag)+1])
            flag += bytes([j]) 
            print(flag)
            break

print(flag)



