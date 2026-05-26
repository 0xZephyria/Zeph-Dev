import http.client
import json
import time

# Load ELF hex
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
print("Deploying contract...")
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

# Try calling standard function selectors:
# - balanceOf(address): selector is 70a08231
# - name(): selector is 06fdde03
# - symbol(): selector is 95d89b41
# - decimals(): selector is 313ce567
# - transfer(address,uint256): selector is a9059cbb

# Prepare calldata for name() -> 06fdde03
# Prepare calldata for balanceOf(0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266)
# -> selector 70a08231 + padded address
padded_address = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266".zfill(64)
balance_of_calldata = "0x70a08231" + padded_address

selectors = {
    "name()": "0x06fdde03",
    "symbol()": "0x95d89b41",
    "decimals()": "0x313ce567",
    "balanceOf(dev)": balance_of_calldata,
}

for name, calldata in selectors.items():
    print(f"Calling {name} with calldata {calldata}...")
    try:
        res = rpc_request("eth_call", [{
            "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "to": contract_address,
            "data": calldata
        }, "latest"])
        print(f"Response: {res}")
    except Exception as e:
        print(f"Call failed: {e}")
