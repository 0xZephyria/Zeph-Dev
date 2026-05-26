import http.client
import json
import time

# Load ELF hex
elf_path = "/Users/karan/sol2zig/vm/polkavm/revive-transfer-example.elf"
with open(elf_path, "rb") as f:
    elf_hex = "0x" + f.read().hex()

# Request helper
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

# 1. Send deploy transaction
print("Deploying PolkaVM ELF contract...")
try:
    tx_hash = rpc_request("eth_sendTransaction", [{
        "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "to": "",
        "gas": "0xf4240", # 1000000
        "value": "0x0",
        "data": elf_hex
    }])
    print(f"Deploy Transaction Submitted! Hash: {tx_hash}")
except Exception as e:
    print("Deployment transaction failed:", e)
    exit(1)

# 2. Wait for block production / receipt
print("Waiting for transaction receipt...")
receipt = None
for _ in range(20):
    time.sleep(1)
    try:
        receipt = rpc_request("eth_getTransactionReceipt", [tx_hash])
    except Exception as e:
        print("Error getting receipt:", e)
    if receipt:
        break

if not receipt:
    print("Error: Timeout waiting for transaction receipt.")
    exit(1)

status = int(receipt["status"], 16)
contract_address = receipt["contractAddress"]
print(f"Receipt Status: {status} (1 = Success)")
print(f"Contract Address Derived: {contract_address}")

if status != 1:
    print("Error: Deployment transaction reverted.")
    exit(1)

# 3. Query contract code via eth_getCode
print("Querying contract code using eth_getCode...")
code = rpc_request("eth_getCode", [contract_address, "latest"])
print(f"Retrieved Code Length: {len(code) - 2} hex chars ({(len(code) - 2) // 2} bytes)")

# Verify that code is indeed the ELF binary
if code.startswith("0x7f454c46") or code.startswith("7f454c46"):
    print("SUCCESS: Retrieved code matches ELF magic header (\\x7fELF)!")
else:
    print(f"FAILURE: Code does not match ELF magic header! Code starts with: {code[:20]}")
    exit(1)

# 4. Query contract via eth_call
print("Performing eth_call to the deployed contract...")
try:
    call_result = rpc_request("eth_call", [{
        "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "to": contract_address,
        "data": "0x"
    }, "latest"])
    print(f"eth_call Response: {call_result}")
except Exception as e:
    print("eth_call failed:", e)
    exit(1)

