from .templates import Output, CoinbaseTransaction, BlockHeader
import socket
import struct
import json
from multiprocessing import Queue
def encode_compactsize(i):
    if i <= 252:
        return f"{i:02x}"
    elif i <= 65535:
        return "fd" + struct.pack("<H", i).hex()
    elif i <= 4294967295:
        return "fe" + struct.pack("<I", i).hex()
    elif i <= 18446744073709551615:
        return "ff" + struct.pack("<Q", i).hex()

class Miner:
    """Miner."""

    def __init__(self,stdout = True,q_flag=False,send_q=Queue() ,out_socket={}):
        """__init__.

        :param address: hex string
        :param amnt: hex string
        :param stdout: boolean
        :param out_socket: dictionary, should contain a port and an address
        """
        self.MAX_NONCE = 0xffffffff
        #self.address = str(hex(int(address,32)))[2:] don't know what this line was
        self.stdout = stdout
        self.socket_flag = False
        self.q_flag = q_flag
        self.send_q=send_q
        if out_socket.get("port") is not None and out_socket.get("address") is not None:
            self.socket_flag = True
            self.sock_address = out_socket["address"]
            self.port = out_socket["port"]

    def construct_coinbasetx(self,output_div,height):
        outputs = []
        for address,amnt in output_div:
            outputs.append(Output(amnt=amnt,address=address))
        outputs.append(Output(amnt="0000000000000000",script_type = "commitment"))
        cnt = str(encode_compactsize(len(outputs)))
        return CoinbaseTransaction(height,output_count=cnt,outputs=outputs)

    def mine(self,output_div,height,version,prev_block,bits,transactions=[])->bool:
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

        coinbase_tx = self.construct_coinbasetx(output_div,height)
        block_header = BlockHeader(version,prev_block,bits,[coinbase_tx]+transactions)
        
        #target calculation 
        exponent = int(bits[0:2],16)
        coefficient = int(bits[2:],16)
        target = coefficient * 2**(8 * (exponent - 3))
        # for testing purpouses:
        #target = target *(16**2)
        small_target = target*(16)

        if self.stdout: print(f"bits:{bits},target: {hex(target)}, exponent = {hex(exponent)}")

        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        if self.socket_flag: 
            s.connect((self.sock_address,self.port))
        nonce = 0

        return_flag = False
        while nonce < self.MAX_NONCE:
            nonce_str = str(hex(nonce))[2:].zfill(8)
            hash = block_header.calc_hash(nonce_str)
            int_hash = int(hash,16)
            if int_hash < target:
                block_header.set_final_nonce(nonce_str)
                if self.stdout: print(block_header.build_final_block())
                if self.socket_flag:
                    block = block_header.build_final_block().encode()
                    length_header = struct.pack("!I",len(block))
                    identity = struct.pack("!B",1)
                    s.sendall(length_header+identity+block)
                if self.q_flag:
                    block = block_header.build_final_block().encode()
                    length_header = struct.pack("!I",len(block))
                    identity = struct.pack("!B",1)
                    msg = length_header+identity+block
                    self.send_q.put(msg)

                return_flag = True
            elif int_hash < small_target:
                if self.stdout: print(f"Nonce: {nonce:08x}, Hash: {hash}")
                if self.socket_flag:
                    block_header_encoded = (block_header.build_hexstring()+nonce_str).encode()
                    identity = struct.pack("!B",0)
                    s.sendall(identity+block_header_encoded)
                if self.q_flag:
                    block_header_encoded = (block_header.build_hexstring()+nonce_str).encode()
                    identity = struct.pack("!B",0)
                    msg = (identity+block_header_encoded)
                    self.send_q.put(msg)

            nonce += 1
        if self.stdout: print("No valid nonce found")
        return return_flag
        
if __name__ == "__main__":
    address = "0638a075aeb98f5d1404fc69dcaed3c4e71ce611"
    miner = Miner()
    prev_block = "00000000f616a555f37553fd69d9ed59315ad48c3894b75e30cc606f84d42ea6"
    success = miner.mine([[address,"e99e060000000000"]],"05","20000000",prev_block ,"1d00ffff")
    print(f"BlockHeader:{block_header.build_block_header()}\n Block:{block_header.build_final_block()}\n, hash: {hash}")
    
 
