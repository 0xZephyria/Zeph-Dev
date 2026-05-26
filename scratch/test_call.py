import http.client
import json

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
    return json.loads(data)

# Address from the previous run
contract_address = "0x85aef50b616241cf2ea82a35a8b78bb8fb3c9c118f3b9e2ed6009bbe798e3d2c"
padded_recipient = "1111111111111111111111111111111111111111".zfill(64)
calldata = "0x48c981e2" + padded_recipient

print("Calling eth_call with transfer calldata...")
res = rpc_request("eth_call", [{
    "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "to": contract_address,
    "value": hex(999999999999999),
    "data": calldata
}, "latest"])
print("Response:", res)
