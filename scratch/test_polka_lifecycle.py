import http.client
import json
import time

# Load PolkaVM ELF
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

print("======================================================================")
print("             STARTING POLKAVM CONTRACT LIFECYCLE TEST                 ")
print("======================================================================")

# 1. Send deploy transaction
print("\n[STEP 1] Deploying PolkaVM ELF Contract...")
tx_hash = rpc_request("eth_sendTransaction", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": "",
    "gas": "0xf4240", # 1,000,000 gas
    "value": "0x0",
    "data": elf_hex
}])
print(f"Deployment TX submitted. Hash: {tx_hash}")

# Wait for receipt
receipt = None
for i in range(20):
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
print(f"Deployed Contract Address: {contract_address}")

if status != 1:
    print("Error: Deployment transaction failed/reverted.")
    exit(1)

# 2. Get code and verify magic
print("\n[STEP 2] Querying contract code via eth_getCode...")
retrieved_code = rpc_request("eth_getCode", [contract_address, "latest"])
print(f"Retrieved bytecode length: {len(retrieved_code) - 2} hex characters")

# Verify magic header (0x7fELF)
if retrieved_code.startswith("0x7f454c46"):
    print("SUCCESS: Bytecode correctly matches ELF magic header (0x7fELF)!")
else:
    print(f"FAILURE: Bytecode does not match ELF magic header! Starts with: {retrieved_code[:20]}")
    exit(1)

# 3. Read call (eth_call)
print("\n[STEP 3] Executing read-only calls (eth_call)...")

# Call with 0x (empty data)
print("Calling with data '0x'...")
res_empty = rpc_request("eth_call", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": contract_address,
    "data": "0x"
}, "latest"])
print(f"Response (0x): {res_empty}")

# Call with 0x00 (dummy selector/input)
print("Calling with data '0x00'...")
res_dummy = rpc_request("eth_call", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": contract_address,
    "data": "0x00"
}, "latest"])
print(f"Response (0x00): {res_dummy}")

# 4. State mutation and value transfer transaction
print("\n[STEP 4] Sending state-mutating transaction (eth_sendTransaction)...")
initial_bal_hex = rpc_request("eth_getBalance", [contract_address, "latest"])
initial_bal = int(initial_bal_hex, 16)
print(f"Initial Contract Balance: {initial_bal} Wei")

transfer_value = 1200000000000000000  # 1.2 ZEPH (0x10f3c2170a890000)
print(f"Sending tx with 1.2 ZEPH value and non-empty data '0x12345678'...")
tx_hash_2 = rpc_request("eth_sendTransaction", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": contract_address,
    "gas": "0x7a120", # 500000
    "value": hex(transfer_value),
    "data": "0x12345678"
}])

# Wait for receipt
receipt_2 = None
for i in range(20):
    time.sleep(0.5)
    receipt_2 = rpc_request("eth_getTransactionReceipt", [tx_hash_2])
    if receipt_2:
        break

if not receipt_2:
    print("Error: Timeout waiting for mutation receipt.")
    exit(1)

status_2 = int(receipt_2["status"], 16)
print(f"Mutation Transaction Status: {status_2} (1 = Success)")

if status_2 != 1:
    print("Error: Transaction failed/reverted.")
    exit(1)

# Check final balance
final_bal_hex = rpc_request("eth_getBalance", [contract_address, "latest"])
final_bal = int(final_bal_hex, 16)
print(f"Final Contract Balance: {final_bal} Wei")

if final_bal == initial_bal + transfer_value:
    print("SUCCESS: Contract balance updated correctly by VM callback!")
else:
    print(f"FAILURE: Balance mismatch. Expected {initial_bal + transfer_value}, got {final_bal}")
    exit(1)

print("\n======================================================================")
print("             ALL LIFECYCLE STEPS SUCCESSFUL!                          ")
print("======================================================================")
