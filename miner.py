from templates import Output, CoinbaseTransaction, BlockHeader

class Miner:
    """Miner."""

    def __init__(self,address, amnt = "00f2052a01000000"):
        """__init__.

        :param address: hex string
        :param amnt: hex string
        """
        self.MAX_NONCE = 0xffffffff
        self.address = address
        #self.address = str(hex(int(address,32)))[2:] don't know what this line was
        self.amnt = amnt
    def mine(self,height,version,prev_block,bits,transactions=[]):
        """mine.

        :param height: hex string
        :param version: hex string
        :param prev_block: hex string
        :param bits: hex string
        :param transactions: transaction list
        """
        output = Output(amnt=self.amnt, address=self.address)
        coinbase_tx = CoinbaseTransaction(height,output_count="01",outputs=[output])
        block_header = BlockHeader(version,prev_block,bits,[coinbase_tx]+transactions)
        
        #target calculation 
        exponent = int(bits[0:2],16)
        coefficient = int(bits[2:],16)
        target = coefficient * 2**(8 * (exponent - 3))
        # for testing purpouses:
        target = target *(16**4)
        small_target = target*(16**3)
        print(f"bits:{bits},target: {hex(target)}, exponent = {hex(exponent)}")
        
        nonce = 0
        while nonce < self.MAX_NONCE:
            nonce_str = str(hex(nonce))[2:].zfill(8)
            hash = block_header.calc_hash(nonce_str)
            int_hash = int(hash,16)
            if int_hash < target:
                block_header.set_final_nonce(nonce_str)
                return (block_header,hash)
            elif int_hash < small_target:
                print(f"Nonce: {nonce}, Hash: {hash}")
            nonce += 1
        print("No valid nonce found")
        return(block_header,"-1")
        
if __name__ == "__main__":
    miner = Miner("0638a075aeb98f5d1404fc69dcaed3c4e71ce611")

    block_header, hash = miner.mine("04","20000000", "000000008fdb91aeacb6168c7e51e591ba8f8bd5c5898185c99596e4e5cc5c97","1d00ffff")
    print(f"BlockHeader:{block_header.build_block_header()}\n Block:{block_header.build_final_block()}\n, hash: {hash}")
    
 
