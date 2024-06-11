# M1 - Corruptible Upgradability Pattern

## Summary
 
MidasAccessControl Store could be corrupted when is upgraded


## Vulnerability Detail

MidasAccessControl main purpose is to provide support to Midas protocol for roles handling and utility methods: setup, grantRoleMult and revokeRoleMult. Also it is an upgradable contract in order to add new functionality or fix bugs but in the case of an upgrade the storage layout will be corrupted because there is no gap slot defined neither in MidasAccessControl or parents in the protocol scope, as the inheritance chart for MidasAccessControl.sol shows:

GREEN: Does have gaps but all of them are from the openzeppelin library

YELLOW: Does not have gaps, all of them are fom the protocol.

![335198763-422402f6-1b0b-405e-9b36-38d677cdd688](https://github.com/nfmelendez/nfmelendez/assets/726950/38696268-0e1f-4582-a793-eeb913561687)


MidasAccessControl is the only important contract that doeesn't have gaps as we can see in the table:

| Contract | Has Gap | Store gap |
|----------|----------|----------|
| DepositVault | YES | 50 |
| RedemptionVault | YES | 51 |
| mTBILL | YES | 50 |
| MidasAccessControl | `NO` | - |



## Impact

Storage of MidasAccessControl might be corrupted during upgrading and causing the role system to be broken and whole protocol unstable.


## Code Snippet

https://github.com/sherlock-audit/2024-05-midas-nfmelendez/blob/main/midas-contracts/contracts/access/MidasAccessControl.sol#L14

## Tool used

- Manual Review
- [https://github.com/sherlock-audit/2022-09-notional-judging/issues/64
](https://github.com/sherlock-audit/2022-09-notional-judging/issues/64)

## Recommendation

Define an appropriate storage gap in MidasAccessControl as follows:

```javascript
    /**
     * @dev leaving a storage gap for futures updates
     */
uint256[50] __gap; 
```

Also a store gaps could be added in parent contracts of MidasAccessControl  but i don't see that necessary. 




# M2 - PausableUpgradeable but doesn't intialize properly

## Summary
Midas `Pausable.sol` upgradeable contract inherit from PausableUpgradeable but doesn't intialize properly
 
## Vulnerability Detail

Upgradeable contract needs to be initilized properly in order to setup them correctly and be compatible with future releases. The `Pausable.sol` contract  in the  `__Pausable_init` method initialize `WithMidasAccessControl` but doesn't call `__Pausable_init` from PausableUpgradeable openzeppelin contract but inherit from it. 

## Impact

PausableUpgradeable assumes `__Pausable_init` will be called to work properly 


## Code Snippet

https://github.com/sherlock-audit/2024-05-midas-nfmelendez/blob/main/midas-contracts/contracts/access/Pausable.sol#L28-L30

## Tool used

- Manual Review


## Recommendation

Call `PausableUpgradeable#__AccessControl_init()` in `Pausable#__Pausable_init()`

```javascript
    function __Pausable_init(address _accessControl) internal onlyInitializing {
        __Pausable_init(); // @audit add this
        __WithMidasAccessControl_init(_accessControl);
    }
```
