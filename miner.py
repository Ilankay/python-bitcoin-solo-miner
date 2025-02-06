from templates import Output, CoinbaseTransaction, BlockHeader

class Miner:
    def __init__(self,address, amnt = "00f2052a01000000"):
        self.MAX_NONCE = 0xffffffff
        self.address = str(hex(int(address,32)))[2:]
        self.amnt = amnt
    def mine(self,height,version,prev_block,bits,transactions=[]):
        output = Output(amnt="00f2052a01000000", address=self.address)
        coinbase_tx = CoinbaseTransaction(height,output_count="01",outputs=[output])
        block_header = BlockHeader(version,prev_block,bits,[coinbase_tx]+transactions)
        target = int(bits[2:],16)*(16**(int(bits[:2],16)*2-6))
        print(f"bits:{bits}, {hex(target)}: target, exponent = {(16**(int(bits[:2],16)*2-6))}")
        small_target = target*(16**3)
        nonce = 0
        while nonce < self.MAX_NONCE:
            nonce_str = str(hex(nonce))[2:].zfill(8)
            hash = block_header.calc_hash(nonce_str)
            int_hash = int(hash,16)
            if int_hash < target:
                return (block_header,hash)
            elif int_hash < small_target:
                print(f"Nonce: {nonce}, Hash: {hash}")
            nonce += 1
        print("No valid nonce found")
        return(block_header,"-1")
        
if __name__ == "__main__":
    miner = Miner("0638a075aeb98f5d1404fc69dcaed3c4e71ce611")

    block_header, hash = miner.mine("04","20000000", "000000008fdb91aeacb6168c7e51e591ba8f8bd5c5898185c99596e4e5cc5c97","1d00ffff")
    print(f"Block: {block_header.build_final_block()}, hash: {hash}")
    
   