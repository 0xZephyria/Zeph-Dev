import http.client
import json
import time

elf_path = "vm/polkavm/revive-transfer-example.elf"
with open(elf_path, "rb") as f:
    elf_hex = "0x" + f.read().hex()

def rpc_request(method, params=[]):
    conn = http.client.HTTPConnection("127.0.0.1", 8545)
    headers = {"Content-Type": "application/json"}
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    })
    conn.request("POST", "/", payload, headers)
    res = conn.getresponse()
    data = res.read().decode()
    conn.close()
    try:
        parsed = json.loads(data)
    except Exception as e:
        print("JSON parse error on raw data:", data)
        raise e
    if "error" in parsed:
        print(f"RPC Method {method} failed with error: {parsed['error']}")
        raise Exception(parsed["error"].get("message", "Unknown error"))
    return parsed.get("result")

print("Deploying PolkaVM Contract...")
tx_hash = rpc_request("eth_sendTransaction", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": "",
    "gas": "0xf4240",
    "value": "0x0",
    "data": elf_hex
}])

receipt = None
for _ in range(20):
    time.sleep(0.5)
    receipt = rpc_request("eth_getTransactionReceipt", [tx_hash])
    if receipt:
        break

contract_address = receipt["contractAddress"]
print(f"Contract deployed at: {contract_address}")

# Prepare parameters:
# Recipient: 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
# Padded to 32 bytes:
padded_addr = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266".zfill(64)
# Amount: 1000 (0x3e8)
# Padded to 32 bytes:
padded_amount = "3e8".zfill(64)

# Test cases:
# 1. transfer(address,uint256) -> selector: a9059cbb
# 2. transfer(address,uint256) byteswapped -> selector: bb9c05a9
# 3. sendEther(address) -> selector: 48c981e2
# 4. sendEther(address) byteswapped -> selector: e281c948

calls = [
    ("transfer(addr,uint256) - BigEndian", "0xa9059cbb" + padded_addr + padded_amount),
    ("transfer(addr,uint256) - LittleEndian", "0xbb9c05a9" + padded_addr + padded_amount),
    ("sendEther(addr) - BigEndian", "0x48c981e2" + padded_addr),
    ("sendEther(addr) - LittleEndian", "0xe281c948" + padded_addr),
]

print("\n--- Executing read-only eth_call tests ---")
for name, calldata in calls:
    print(f"Calling {name}...")
    try:
        res = rpc_request("eth_call", [{
            "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "to": contract_address,
            "data": calldata
        }, "latest"])
        print(f"Response: {res}")
    except Exception as e:
        print(f"Call failed: {e}")

print("\n--- Executing mutating transaction tests ---")
for name, calldata in calls:
    print(f"Sending transaction to {name}...")
    try:
        tx_hash_call = rpc_request("eth_sendTransaction", [{
            "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "to": contract_address,
            "gas": "0xf4240",
            "value": "0x3e8", # 1000 Wei
            "data": calldata
        }])
        
        # Wait for receipt
        receipt_call = None
        for _ in range(20):
            time.sleep(0.3)
            receipt_call = rpc_request("eth_getTransactionReceipt", [tx_hash_call])
            if receipt_call:
                break
        
        status = int(receipt_call["status"], 16)
        print(f"Tx Status: {status} (1 = Success)")
    except Exception as e:
        print(f"Tx failed: {e}")
