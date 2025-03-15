from miner import Miner
from multiprocessing import Process
import time
def big_to_little(x:str):
    out = ""
    for i,j in zip(x[::2][::-1],x[::-2]):
        out += i+j
    return out       

def mine_block_process(p:int):
    height = "04"
    version = "20000000"
    num = 10
    bits = "1d00ffff"

    miner = Miner("0638a075aeb98f5d1404fc69dcaed3c4e71ce611")
    prev_block = "00000000f616a555f37553fd69d9ed59315ad48c3894b75e30cc606f84d42ea6" #previous block must be reversed!!!!!!!
    block_header, hash = miner.mine(height,version,prev_block ,bits)
    print(f"process {i}:")
    print(f"BlockHeader:{block_header.build_block_header()}\n Block:{block_header.build_final_block()}\n, hash: {hash}")
print(big_to_little("abcd"))    
processes = []
num = 10
for i in range(num):
    p = Process(target = mine_block_process,args=(i,))
    time.sleep(1.5)
    p.start()
    processes.append(i)
 
