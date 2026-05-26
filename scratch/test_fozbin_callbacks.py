import http.client
import json
import time

# Load TokenTest.fozbin
fozbin_path = "TokenTest.fozbin"
with open(fozbin_path, "rb") as f:
    fozbin_hex = "0x" + f.read().hex()

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

# 1. Deploy
print("1. Deploying TokenTest.fozbin contract...")
tx_hash = rpc_request("eth_sendTransaction", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": "",
    "gas": "0xf4240", # 1000000
    "value": "0x0",
    "data": fozbin_hex
}])
print(f"Deploy Transaction Submitted! Hash: {tx_hash}")

# Wait for receipt
receipt = None
for _ in range(20):
    time.sleep(0.5)
    receipt = rpc_request("eth_getTransactionReceipt", [tx_hash])
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

# 2. Query contract code via eth_getCode
print("\n2. Querying contract code using eth_getCode...")
code = rpc_request("eth_getCode", [contract_address, "latest"])
print(f"Retrieved Code Length: {len(code) - 2} hex chars ({(len(code) - 2) // 2} bytes)")

# Verify that code is indeed the FORG binary
if code.startswith("0x464f5247"):
    print("SUCCESS: Deployed bytecode matches FORG magic header!")
else:
    print(f"FAILURE: Code does not match FORG magic header! Code starts with: {code[:20]}")
    exit(1)

# 3. Query selectors via eth_call
print("\n3. Testing selectors via eth_call callbacks...")

# List of selectors from vm/polkavm/compiler/aot.zig
selectors = [
    # Original selectors (big-endian hex)
    ("a0873bbc (Original)", "0xa0873bbc"),
    ("6f91d85a (Original)", "0x6f91d85a"),
    ("ba4d2440 (Original)", "0xba4d2440"),
    ("1ce900f6 (Original)", "0x1ce900f6"),
    ("25b04e4e (Original)", "0x25b04e4e"),
    ("47779aaa (Original)", "0x47779aaa"),
    ("0dc9e26b (Original)", "0x0dc9e26b"),
    # Byteswapped (little-endian hex representation)
    ("a0873bbc (Byteswapped)", "0xbc3b87a0"),
    ("6f91d85a (Byteswapped)", "0x5ad8916f"),
    ("ba4d2440 (Byteswapped)", "0x40244dba"),
    ("1ce900f6 (Byteswapped)", "0xf600e91c"),
    ("25b04e4e (Byteswapped)", "0x4e4eb025"),
    ("47779aaa (Byteswapped)", "0xaa9a7747"),
    ("0dc9e26b (Byteswapped)", "0x6be2c90d")
]

for desc, sel in selectors:
    print(f"\nCalling {desc} with data {sel}...")
    try:
        res = rpc_request("eth_call", [{
            "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "to": contract_address,
            "data": sel
        }, "latest"])
        print(f"Response: {res}")
    except Exception as e:
        print(f"Call failed: {e}")
