import http.client
import json
import time

elf_path = "/Users/karan/sol2zig/vm/polkavm/revive-transfer-example.elf"
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
    parsed = json.loads(data)
    if "error" in parsed:
        print(f"RPC Method {method} failed with error: {parsed['error']}")
        raise Exception(parsed["error"].get("message", "Unknown error"))
    return parsed.get("result")

# 1. Deploy
print("1. Deploying contract...")
tx_hash = rpc_request("eth_sendTransaction", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": "",
    "gas": "0xf4240",
    "value": "0x0",
    "data": elf_hex
}])

# Wait for receipt
receipt = None
for _ in range(20):
    time.sleep(0.5)
    receipt = rpc_request("eth_getTransactionReceipt", [tx_hash])
    if receipt:
        break

contract_address = receipt["contractAddress"]
print(f"Contract deployed at: {contract_address}")

# 2. Get initial balance
bal_hex_1 = rpc_request("eth_getBalance", [contract_address, "latest"])
bal_1 = int(bal_hex_1, 16)
print(f"Initial Contract Balance: {bal_1} wei")

# 3. Send transaction with value to contract address
print("3. Sending transaction with 1.2 ZEPH value and non-empty calldata...")
tx_hash_2 = rpc_request("eth_sendTransaction", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": contract_address,
    "gas": "0x7a120", # 500000
    "value": "0x10f3c2170a890000", # 1.2 ZEPH
    "data": "0x12345678"
}])

# Wait for receipt
receipt_2 = None
for _ in range(20):
    time.sleep(0.5)
    receipt_2 = rpc_request("eth_getTransactionReceipt", [tx_hash_2])
    if receipt_2:
        break

status_2 = int(receipt_2["status"], 16)
print(f"Transaction status: {status_2} (1 = Success)")

# 4. Get final balance
bal_hex_2 = rpc_request("eth_getBalance", [contract_address, "latest"])
bal_2 = int(bal_hex_2, 16)
print(f"Final Contract Balance: {bal_2} wei")

if bal_2 > bal_1:
    print("SUCCESS: Contract balance increased via transaction callback execution!")
else:
    print("FAILURE: Contract balance did not change.")
