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

print("======================================================================")
print("             POLKAVM FUNCTION CALL & EXECUTION TEST                   ")
print("======================================================================")

# 1. Deploy
print("\n1. Deploying PolkaVM Contract...")
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

# 2. Get initial balance of recipient
recipient = "0x1111111111111111111111111111111111111111"
init_bal_hex = rpc_request("eth_getBalance", [recipient, "latest"])
init_bal = int(init_bal_hex, 16)
print(f"\n2. Initial recipient balance ({recipient}): {init_bal} Wei")

# 3. Call sendEther(address)
# Selector: 0x48c981e2
# Calldata: selector + 32-byte padded address
padded_recipient = "1111111111111111111111111111111111111111".zfill(64)
calldata = "0x48c981e2" + padded_recipient
transfer_value = 999999999999999  # ~0.001 ZEPH

print(f"\n3. Sending tx calling sendEther(address) with {transfer_value} Wei value...")
tx_hash_call = rpc_request("eth_sendTransaction", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": contract_address,
    "gas": "0xf4240",
    "value": hex(transfer_value),
    "data": calldata
}])

# Wait for receipt
receipt_call = None
for _ in range(20):
    time.sleep(0.5)
    receipt_call = rpc_request("eth_getTransactionReceipt", [tx_hash_call])
    if receipt_call:
        break

status = int(receipt_call["status"], 16)
print(f"Transaction Receipt Status: {status} (1 = Success)")

if status != 1:
    print("Error: Mutation transaction reverted.")
    exit(1)

# 4. Check final balance of recipient
final_bal_hex = rpc_request("eth_getBalance", [recipient, "latest"])
final_bal = int(final_bal_hex, 16)
print(f"\n4. Final recipient balance ({recipient}): {final_bal} Wei")

if final_bal == init_bal + transfer_value:
    print("\nSUCCESS: The PolkaVM contract successfully decoded the selector, parsed the address, and executed the transfer host call!")
else:
    print(f"\nFAILURE: Recipient balance did not increase correctly. Expected {init_bal + transfer_value}, got {final_bal}")
    exit(1)

print("======================================================================")
