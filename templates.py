import hashlib
import time
import struct
from binascii import hexlify, unhexlify

def switch_endian(x:str):
    """switch_endian.

    :param x:
    :type x: str
    """
    out = ""
    for i,j in zip(x[::2][::-1],x[::-2]):
        out += i+j
    return out       


def hash256(a):
    """hash256.

    :param a:
    """
    a1 = unhexlify(a)
    h = hashlib.sha256(hashlib.sha256(a1).digest()).digest()
    return hexlify(h).decode('utf-8')

def double_hash256(a, b):
    """double_hash256.

    :param a:
    :param b:
    """
    # Reverse inputs before and after hashing
    # due to big-endian / little-endian nonsense
    
    a1 = a[::-1]
    b1 = b[::-1]
    
    contcat = a1+b1
            
    h = hashlib.hash256(hashlib.hash256(bytes.fromhex(contcat)).digest()).digest()
    return h

class Template:
    """
    this class is for the template object,
    the the class will consist of a dictionary of all the fields in the template which will be either
    a hex string a template or a list of templtes.
    it will have a method to build the hex string of the template and a method to convert the hex string to an integer.
    """

    def __init__(self):
        """__init__."""
        self.template = {}
        self.template_list = []

    def add_field(self, field_name, field_value):
        """add_field.

        :param field_name:
        :param field_value:
        """
        self.template[field_name] = field_value
        self.template_list.append((field_name, field_value))

    def build_hexstring(self):
        """build_hexstring."""
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
        """build_int."""
        return int(self.build_hexstring(), 16)


class Transaction(Template):
    """
    this class is for the transaction object
    """

    def __init__(self, version="", marker="", flag="", input_count="", inputs=[], output_count="", outputs=[], locktime=""):
        """__init__.

        :param version:
        :param marker:
        :param flag:
        :param input_count:
        :param inputs:
        :param output_count:
        :param outputs:
        :param locktime:
        """
        super().__init__()
        self.add_field("version", version)
        self.add_field("marker", marker)
        self.add_field("flag", flag)
        self.add_field("input count", input_count)
        self.add_field("inputs", inputs)
        self.add_field("output count", output_count)
        self.add_field("outputs", outputs)
        self.add_field("locktime", locktime)
    
    def calc_txid(self):
        to_hash = self.template["version"]+self.template["input count"]
        for input in self.template["inputs"]:
            to_hash += input.build_hexstring()
        to_hash += self.template["output count"]
        for output in self.template["outputs"]:
            to_hash += output.build_hexstring()
        to_hash += self.template["locktime"]
        return hash256(to_hash)


class Output(Template):
    """
    this class is for the output object we are using P2WPKH
    """

    def __init__(self, amnt="", address="", script_type="P2WPKH",wtxids = []):
        """__init__.

        :param amnt: input in big endian byte order
        :param address: 
        :param script_type: P2PKH | P2WPKH | commitment
        :param wtxids: used only in case of script type being  commitment
        """
        super().__init__()
        if script_type == "P2WPKH":
            scriptPubKey = self.construct_script_sig_P2WPKH(address)
            scriptPubKey_size = "16"  # compactsize of 22 the size of a p2wpkh scriptPubKey
        elif script_type == "P2PKH":
            scriptPubKey = self.construct_script_sig_P2PKH(address)
            scriptPubKey_size = "19"
        elif script_type == "commitment":
            scriptPubKey = self.construct_wtxid_commitment_script(wtxids)
            scriptPubKey_size = "26"
        else:
            raise Exception("bad script type")

        self.add_field("amnt", switch_endian(amnt))
        self.add_field("scriptPubKey size", scriptPubKey_size)
        self.add_field("scriptPubKey", scriptPubKey)

    def construct_script_sig_P2PKH(self, address):
        """construct_script_sig_P2PKH.

        :param address:
        """
        OP_DUP = "76"
        OP_HASH160 = "a9"
        OP_PUSH_20 = "14"
        OP_EQUALVERIFY = "88"
        OP_CHECKSIG = "ac"
        return OP_DUP+OP_HASH160+OP_PUSH_20+address+OP_EQUALVERIFY+OP_CHECKSIG
    
    def construct_script_sig_P2WPKH(self,address):
        """construct_script_sig_P2WPKH.

        :param address:
        """
        OP0 = "00"
        OP_PUSH_20 = "14"
        return OP0+OP_PUSH_20+address

    def construct_wtxid_commitment_script(self,wtxids=[]):
        """construct_wtxid_commitment_script.

        :param wtxids: a list of all wtxids excluding the coinbase wtxid
        """
        coinbase_wtxid = "0000000000000000000000000000000000000000000000000000000000000000"
        witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000"
        wtxids = [coinbase_wtxid]+wtxids
        wtxid_commitment = hash256(self._calc_wtxid_root(wtxids)+witness_reserved_value)

        OP_RETURN = "6a"
        OP_PUSHBYTES_36 = "24"
        commitment_header = "aa21a9ed"
        return OP_RETURN+OP_PUSHBYTES_36+commitment_header+wtxid_commitment

    def _calc_wtxid_root(self,wtxids):
        if len(wtxids) == 1:
            return wtxids[0] 
        if len(wtxids) % 2 != 0:
            wtxids.append(wtxids[-1])
        new_wtxids = []
        for i in range(0,len(wtxids),2):
            new_wtxids.append(double_hash256(wtxids[i],wtxids[i+1]))
        return self._calc_wtxid_root(new_wtxids)




class CoinbaseInput(Template):
    """
    the class if for the input object P2WPKH
    """
    def __init__(self,height):
        """__init__.

        :param height:
        """
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
        """build_script_sig.

        :param height:
        """
        OP_PUSH01 = "01"
        return OP_PUSH01+height

class CoinbaseWitness(Template):
    """
    the class is for the witness object
    """
    def __init__(self):
        """__init__."""
        super().__init__()
        stack_count = "01"
        size = "20"
        item = "0000000000000000000000000000000000000000000000000000000000000000"
        self.add_field("stack count", stack_count)
        self.add_field("size", size)
        self.add_field("item", item)
    
class  CoinbaseTransaction(Template):
    """CoinbaseTransaction."""

    def __init__(self, height, output_count="", outputs=[]):
        """__init__.

        :param height: the height of the block
        :param output_count: the number of all outputs including the wtxid commitment
        :param outputs: a list of the outputs including the wtxid commitment
        """
        super().__init__()
        version = "01000000"
        marker = "00"
        flag = "01"
        input_count = "01"
        input = CoinbaseInput(height)
        witness = CoinbaseWitness()
        locktime = "00000000"
     
        self.add_field("version", version)
        #self.add_field("marker", marker)
        #self.add_field("flag", flag)
        self.add_field("input count", input_count)
        self.add_field("input", input)
        self.add_field("output count", output_count)
        self.add_field("outputs", outputs)
        #self.add_field("witness",witness)
        self.add_field("locktime", locktime)

    def calc_txid(self):
        to_hash = self.template["version"]+self.template["input count"]+self.template["input"].build_hexstring()+self.template["output count"]
        for output in self.template["outputs"]:
            to_hash += output.build_hexstring()
        to_hash += self.template["locktime"]
        return hash256(to_hash)

class BlockHeader(Template):
    """BlockHeader."""

    def __init__(self, version="", prev_block="", bits="", txns=[]):
        """__init__.

        :param version: in big endian byte order
        :param prev_block: in big endian byte order
        :param bits: in big endian byte order
        :param txns:
        """
        super().__init__()
        merkle_root = self.calc_merkle_root(txns)
        timestamp = switch_endian(hex(int(time.time()))[2:])
        nonce = "00000000"
        txn_count = str(hex(len(txns)))[2:]
        if len(txn_count) % 2 != 0:
            txn_count = "0"+txn_count
        self.txns = txns
        
        self.add_field("version", switch_endian(version))
        self.add_field("prev_block", switch_endian(prev_block))
        self.add_field("merkle_root", merkle_root) 
        self.add_field("timestamp", timestamp)
        self.add_field("bits", switch_endian(bits))
        self.final_nonce = nonce
        self.no_nonce = self.build_hexstring()
    def build_hexstring_nonce(self,nonce:str):
        """build_hexstring_nonce.

        :param nonce:
        :type nonce: str
        """
        return self.no_nonce+nonce
   
    def calc_merkle_root(self,txns:list):
        """calc_merkle_root.

        :param txns:
        :type txns: list
        """
        if len(txns) == 1:
            return txns[0].calc_txid() 
        if len(txns) % 2 != 0:
            txns.append(txns[-1])
        new_txns = []
        for i in range(0,len(txns),2):
            new_txns.append(double_hash256(txns[i].calc_txid(),txns[i+1].calc_txid()))
        return self.calc_merkle_root(new_txns)
    
    def calc_hash(self,nonce:str):
        """calc_hash.

        :param nonce:
        :type nonce: str
        """
        self.nonce = nonce
        return hash256(self.build_hexstring_nonce(nonce))[::-1]
    

    def update_time(self):
        """update_time."""
        self.template_list[3][1] = switch_endian(hex(int(time.time()))[2:])
        
    def set_final_nonce(self,nonce:str):
        """set_final_nonce.

        :param nonce:
        :type nonce: str
        """
        self.final_nonce = nonce

    def build_block_header(self):
        """build_block_header."""
        return self.build_hexstring_nonce(self.final_nonce)

    def build_final_block(self):
        """build_final_block."""
        return self.build_hexstring_nonce(self.final_nonce)+"01"+''.join([txn.build_hexstring() for txn in self.txns])

if __name__ == "__main__":
    print("test1")
    output = Output(amnt="00f2052a01000000", address="4f36e8847f8a508f46023d63f347044c2744ae32")
    print("test2")
    commitment_output = Output(amnt="0000000000000000",script_type = "commitment")
    #print(output.build_hexstring())
    coinbast_tx = CoinbaseTransaction("05",output_count="02",outputs=[output,commitment_output])
    print("transaction")
    print(coinbast_tx.build_hexstring())
    print("txid")
    print(coinbast_tx.calc_txid())
