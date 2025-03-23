from .templates import Output, CoinbaseTransaction, BlockHeader
import socket
import struct
class Miner:
    """Miner."""

    def __init__(self,address, amnt = "00f2052a01000000",stdout = True, out_socket={}):
        """__init__.

        :param address: hex string
        :param amnt: hex string
        :param stdout: boolean
        :param out_socket: dictionary, should contain a port and an address
        """
        self.MAX_NONCE = 0xffffffff
        self.address = address
        #self.address = str(hex(int(address,32)))[2:] don't know what this line was
        self.amnt = amnt
        self.stdout = stdout
        self.socket_flag = False
        if out_socket.get("port") is not None and out_socket.get("address") is not None:
            self.socket_flag = True
            self.sock_address = out_socket["address"]
            self.port = out_socket["port"]

    def mine(self,height,version,prev_block,bits,transactions=[])->bool:
        """mine.
        this returns a boolean of whether a block was found or not
        if the socket is activated then it will either send through the socket the block_header with a high hash, which will start 
        with a zero digit or it will send the full block that can be submitted that will start with a one digit.

        :param height: hex string
        :param version: hex string
        :param prev_block: hex string
        :param bits: hex string
        :param transactions: transaction list
        """
        commitment_output = Output(amnt="0000000000000000",script_type = "commitment")
        output = Output(amnt=self.amnt, address=self.address)
        coinbase_tx = CoinbaseTransaction(height,output_count="02",outputs=[output,commitment_output])
        block_header = BlockHeader(version,prev_block,bits,[coinbase_tx]+transactions)
        
        #target calculation 
        exponent = int(bits[0:2],16)
        coefficient = int(bits[2:],16)
        target = coefficient * 2**(8 * (exponent - 3))
        # for testing purpouses:
        #target = target *(16**4)
        small_target = target*(16)
        if self.stdout: print(f"bits:{bits},target: {hex(target)}, exponent = {hex(exponent)}")
        
        nonce = 0
        while nonce < self.MAX_NONCE:
            nonce_str = str(hex(nonce))[2:].zfill(8)
            hash = block_header.calc_hash(nonce_str)
            int_hash = int(hash,16)
            if int_hash < target:
                block_header.set_final_nonce(nonce_str)
                if self.stdout: print(block_header.build_final_block())
                if self.socket_flag:
                    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                        s.connect((self.sock_address,self.port))
                        block = block_header.build_final_block().encode()
                        length_header = struct.pack("!I",len(block))
                        identity = struct.pack("!B",1)
                        s.sendall(length_header+identity+block)

                return True
            elif int_hash < small_target:
                if self.stdout: print(f"Nonce: {nonce}, Hash: {hash}")
                if self.socket_flag:
                    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                        s.connect((self.sock_address,self.port))
                        block_header_encoded = (block_header.build_hexstring()+nonce_str).encode()
                        header = struct.pack("!I",len(block_header_encoded))
                        identity = struct.pack("!B",0)
                        s.sendall(header+identity+block_header_encoded)
            nonce += 1
        if self.stdout: print("No valid nonce found")
        return False
        
if __name__ == "__main__":
    miner = Miner("0638a075aeb98f5d1404fc69dcaed3c4e71ce611")
    prev_block = "00000000f616a555f37553fd69d9ed59315ad48c3894b75e30cc606f84d42ea6"
    block_header, hash = miner.mine("05","20000000",prev_block ,"1d00ffff")
    print(f"BlockHeader:{block_header.build_block_header()}\n Block:{block_header.build_final_block()}\n, hash: {hash}")
    
 
