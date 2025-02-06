import hashlib
import time
import struct
from binascii import hexlify, unhexlify

def sha256(a):
    a1 = unhexlify(a)
    h = hashlib.sha256(hashlib.sha256(a1).digest()).digest()
    return hexlify(h)[::-1].decode('utf-8')

def double_sha256(a, b):
    # Reverse inputs before and after hashing
    # due to big-endian / little-endian nonsense
    
    a1 = a[::-1]
    b1 = b[::-1]
    
    contcat = a1+b1
            
    h = hashlib.sha256(hashlib.sha256(bytes.fromhex(contcat)).digest()).digest()
    return h

class Template:
    """
    this class is for the template object,
    the the class will consist of a dictionary of all the fields in the template which will be either
    a hex string a template or a list of templtes.
    it will have a method to build the hex string of the template and a method to convert the hex string to an integer.
    """

    def __init__(self):
        self.template = {}
        self.template_list = []

    def add_field(self, field_name, field_value):
        self.template[field_name] = field_value
        self.template_list.append((field_name, field_value))

    def build_hexstring(self):
        hex_string = ""
        for field in self.template_list:
            if isinstance(field[1], str):
                hex_string += field[1]
            elif isinstance(field[1], list):
                hex_string += ''.join([template.build_hexstring()
                                      for template in field[1]])
            elif isinstance(field[1],Template):
                hex_string += field[1].build_hexstring()
            else:
                raise ValueError("field value must be a string or a list of templates")
        return hex_string

    def build_int(self):
        return int(self.build_hexstring(), 16)


class Transaction(Template):
    """
    this class is for the transaction object
    """

    def __init__(self, version="", marker="", flag="", input_count="", inputs=[], output_count="", outputs=[], locktime=""):
        super().__init__()
        self.add_field("version", version)
        self.add_field("marker", marker)
        self.add_field("flag", flag)
        self.add_field("input count", input_count)
        self.add_field("inputs", inputs)
        self.add_field("output count", output_count)
        self.add_field("outputs", outputs)
        self.add_field("locktime", locktime)


class Output(Template):
    """
    this class is for the output object we are using P2WPKH
    """

    def __init__(self, amnt="", address=""):
        super().__init__()
        scriptPubKey = self.construct_script_sig_P2WPKH(address)
        scriptPubKey_size = "16"  # compactsize of 22 the size of a p2wpkh scriptPubKey
        self.add_field("amnt", amnt)
        self.add_field("scriptPubKey size", scriptPubKey_size)
        self.add_field("scriptPubKey", scriptPubKey)

    def construct_script_sig_P2PKH(self, address):
        OP_DUP = "76"
        OP_PUSH160 = "a9"
        OP_EQUALVERIFY = "88"
        OP_CHECKSIG = "ac"
        return OP_DUP+OP_PUSH160+address+OP_EQUALVERIFY+OP_CHECKSIG
    
    def construct_script_sig_P2WPKH(self,address):
        OP0 = "00"
        OP_PUSH_20 = "14"
        return OP0+OP_PUSH_20+address


class CoinbaseInput(Template):
    """
    the class if for the input object P2WPKH
    """
    def __init__(self,height):
        super().__init__()
        txid = "0000000000000000000000000000000000000000000000000000000000000000"
        vout = "ffffffff"
        sequence = "fffffffe"
        scriptSig = self.build_script_sig(height)
        scriptSig_size = str(hex(len(scriptSig)//2))[2:]
        if len(scriptSig_size) % 2 != 0:
            scriptSig_size = "0"+scriptSig_size
        self.add_field("txid", txid)
        self.add_field("vout", vout)
        self.add_field("scriptSig size", scriptSig_size)
        self.add_field("scriptSig", scriptSig)
        self.add_field("sequence", sequence)
    def build_script_sig(self,height): 
        OP_PUSH01 = "01"
        return OP_PUSH01+height

class CoinbaseWitness(Template):
    """
    the class is for the witness object
    """
    def __init__(self):
        super().__init__()
        stack_count = "01"
        size = "20"
        item = "0000000000000000000000000000000000000000000000000000000000000000"
        self.add_field("stack count", stack_count)
        self.add_field("size", size)
        self.add_field("item", item)
    
class  CoinbaseTransaction(Template):
    def __init__(self, height, output_count="", outputs=[]):
        super().__init__()
        version = "20000000"
        marker = "00"
        flag = "01"
        input_count = "01"
        input = CoinbaseInput(height)
        witness = CoinbaseWitness()
        locktime = "00000000"
        
        self.add_field("version", version)
        self.add_field("marker", marker)
        self.add_field("flag", flag)
        self.add_field("input count", input_count)
        self.add_field("input", input)
        self.add_field("output count", output_count)
        self.add_field("outputs", outputs)
        self.add_field("witness",witness)
        self.add_field("locktime", locktime)

class BlockHeader(Template):
    def __init__(self, version="", prev_block="", bits="", txns=[]):
        super().__init__()
        merkle_root = self.calc_merkle_root(txns)
        timestamp = str(hex(struct.unpack('>I',struct.pack('<I',int(time.time())))[0]))[2:]
        nonce = "00000000"
        txn_count = str(hex(len(txns)))[2:]
        if len(txn_count) % 2 != 0:
            txn_count = "0"+txn_count
        self.txns = txns
        
        self.add_field("version", version)
        self.add_field("prev_block", prev_block)
        self.add_field("merkle_root", merkle_root)
        self.add_field("timestamp", timestamp)
        self.add_field("bits", bits)
        self.no_nonce = self.build_hexstring()
    def build_hexstring_nonce(self,nonce):
        return self.no_nonce+nonce
    
    def calc_merkle_root(self,txns):
        if len(txns) == 1:
            return txns[0].template["input"].template["txid"]
        if len(txns) % 2 != 0:
            txns.append(txns[-1])
        new_txns = []
        for i in range(0,len(txns),2):
            new_txns.append(double_sha256(txns[i].template["input"].template["txid"],txns[i+1].template["input"].template["txid"]))
        return self.calc_merkle_root(new_txns)
    
    def calc_hash(self,nonce):
        self.nonce = nonce
        return sha256(self.build_hexstring_nonce(nonce))
    

    def update_time(self):
        self.template_list[3][1] = str(hex(struct.unpack('>I',struct.pack('<I',int(time.time())))[0]))[2:]
        
    def build_final_block(self):
        return self.build_hexstring()+"01"+''.join([txn.build_hexstring() for txn in self.txns])

if __name__ == "__main__":
    output = Output(amnt="00f2052a01000000", address="4f36e8847f8a508f46023d63f347044c2744ae32")
    #print(output.build_hexstring())
    coinbast_tx = CoinbaseTransaction("05",output_count="01",outputs=[output])
    print(coinbast_tx.build_hexstring())