# M1 - Front-running griefing attack on PerAddressContinuousVestingMerkleDistributorFactory and PerAddressTrancheVestingMerkleDistributorFactory

## Summary

The `deployDistributor` method in PerAddressContinuousVestingMerkleDistributorFactory and PerAddressTrancheVestingMerkleDistributorFactory calls `Clones.cloneDeterministic` (that uses CREATE2 opcode) with a generated salt to create a deterministic address but an attacker can frontrun the call with same arguments, generate a contract in the same address and always the user transaction will revert.   

## Vulnerability Detail
Since the salt is not created with the `msg.sender` any attacker can front-run the user when calling `deployDistributor` with same parameters and  user transaction will revert

## Impact
All User transaction will fail.

## Code Snippet

https://github.com/sherlock-audit/2024-05-tokensoft-distributor-contracts-update-nfmelendez/blob/main/contracts/packages/hardhat/contracts/claim/factory/PerAddressTrancheVestingMerkleDistributorFactory.sol#L59-L61

https://github.com/sherlock-audit/2024-05-tokensoft-distributor-contracts-update-nfmelendez/blob/main/contracts/packages/hardhat/contracts/claim/factory/PerAddressContinuousVestingMerkleDistributorFactory.sol#L59-L61

https://github.com/sherlock-audit/2024-05-tokensoft-distributor-contracts-update-nfmelendez/blob/main/contracts/packages/hardhat/contracts/claim/factory/PerAddressTrancheVestingMerkleDistributorFactory.sol#L20-L38

## Tool used
- Vscode
- [solodit #1](https://solodit.xyz/issues/m-02-possible-front-running-griefing-attack-on-nft-creations-pashov-none-baton-launchpad-markdown)
- [solodit #2](https://solodit.xyz/issues/m-11-factorycreate-predictability-of-pool-address-creates-multiple-issues-code4rena-caviar-caviar-private-pools-git)


## Recommendation

Add the `msg.sender` when creating the salt in both contracts: PerAddressContinuousVestingMerkleDistributorFactory and PerAddressTrancheVestingMerkleDistributorFactory

```javascript
   function _getSalt(
        IERC20 _token, 
        uint256 _total, 
        string memory _uri, 
        bytes32 _merkleRoot, 
        uint160 _maxDelayTime, 
        address _owner,
        uint256 _nonce
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(
            _token,
            _total,
            _uri,
            _merkleRoot,
            _maxDelayTime,
            _owner,
            msg.sender, //@audit add msg.sender here
            _nonce
        ));
    }
```

<br>

# M2 - PerAddressTrancheVestingMerkleDistributor claim will always revert

## Summary
`claim` method in `PerAddressTrancheVestingMerkleDistributor` is sending empty data instead of tranches data to `_executeClaim` method and will always fail because `claimableAmount` will be 0 in `DistributorInitializable#_executeClaim` when execute claim.

## Vulnerability Detail

`PerAddressTrancheVestingMerkleDistributor#claim` is sending empty data to `_executeClaim` method as parameter instead of tranches data so the PerAddressTrancheVestingInitializable#getVestedFraction will always return 0 and that makes  DistributorInitializable#getClaimableAmount return 0 that will make claimableAmount equal 0 in DistributorInitializable#_executeClaim and will revert when `require(claimableAmount > 0, "...");` in `DistributorInitializable#_executeClaim`.


## Impact

PerAddressTrancheVestingMerkleDistributor is broken, Users can't claim because will always revert with message `"Distributor: no more tokens claimable right now"`

## Code Snippet

`claim` method in `PerAddressTrancheVestingMerkleDistributor` is sending empty data to `_executeClaim`

https://github.com/sherlock-audit/2024-05-tokensoft-distributor-contracts-update-nfmelendez/blob/main/contracts/packages/hardhat/contracts/claim/factory/PerAddressTrancheVestingMerkleDistributor.sol#L62


Always revert in  `require(claimableAmount > 0, "...");` :

https://github.com/sherlock-audit/2024-05-tokensoft-distributor-contracts-update-nfmelendez/blob/main/contracts/packages/hardhat/contracts/claim/factory/DistributorInitializable.sol#L75-L76


## Tool used

Manual Review

## Recommendation

Claim function should be pretty much like `PerAddressTrancheVestingMerkle#claim`

```javascript
  function claim(
    uint256 index, 
    address beneficiary,
    uint256 totalAmount,
    Tranche[] calldata tranches, //@audit add tranches data here
    bytes32[] calldata merkleProof
  )
    external
    validMerkleProof(keccak256(abi.encodePacked(index, beneficiary, totalAmount, abi.encode(tranches))), merkleProof)
    nonReentrant
  {
    bytes memory data = abi.encode(tranches);
    uint256 claimedAmount = _executeClaim(beneficiary, totalAmount, data);
    _settleClaim(beneficiary, claimedAmount);
  }
  ```

<br>

# M3 - Many distributor creation transaction with valid merkle root will revert because of a downcasting

## Summary

A downcasting from uint256 to uint160 makes many creation of distributions using a valid merkle root to revert. 

## Vulnerability Detail
Solidity truncates the higher-order bits when downcast, it doesn't fail or revert. In order to create a `salt` for the FairQueue to create a pseudorandom value the bytes of the merkle root is processed as a downcast `uint160(uint256(byte32))` that truncates the higher-order bits but FairQueue when creates the pseudorandom number it reverts if the salt is 0 with message "I demand more randomness".
So there are many merkle roots that will fail when creating a distribution, every merkle root that has the pattern `0xffffffffffffffffffffffff0000000000000000000000000000000000000000` where  `ffffffffffffffffffffffff` can be any hex combination when is downcasted to uint160 will be 0 and therefore the transaction will revert.

Affected Distributions:
- ContinuousVestingMerkle
- CrosschainMerkleDistributor
- CrosschainTrancheVestingMerkle
- PerAddressContinuousVestingMerkle
- PerAddressTrancheVestingMerkle
- TrancheVestingMerkle

POC

```
➜ uint256 merkleroot = 0xffffffffffffffffffffffff0000000000000000000000000000000000000000
➜ uint160 salt = uint160(merkleroot);
➜ salt
Type: uint160
├ Hex: 0x
├ Hex (full word): 0x0
└ Decimal: 0
```

## Impact

All transactions that creates a merkle distribution with valid merkleroot that match the mentioned pattern will revert with message: "I demand more randomness"

## Code Snippet

Example of downcasting:

https://github.com/sherlock-audit/2024-05-tokensoft-distributor-contracts-update-nfmelendez/blob/main/contracts/packages/hardhat/contracts/claim/factory/PerAddressContinuousVestingMerkleDistributor.sol#L24

Revert code:

https://github.com/sherlock-audit/2024-05-tokensoft-distributor-contracts-update-nfmelendez/blob/9cf79a2d1608d5bce2b058078c7d3e70877ba52d/contracts/packages/hardhat/contracts/utilities/FairQueue.sol#L38

## Tool used

Manual Review

## Recommendation

I would not downcast and accept all possible merkle roots using a uint256 instead of a uint160 to create the pseudo random number

```javascript
  function _setPseudorandomValue(uint160 salt) internal { // @audit modify this to uint256 salt and generate a psudo random number without overflowing
    if (distancePerSecond == 0) {
      return;
    }
    require(salt > 0, 'I demand more randomness');
    randomValue = uint160(uint256(blockhash(block.number - 1))) ^ salt;
  }
  ```