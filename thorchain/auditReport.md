## Router transferOutAndCallV5:  Fee on transfer tokens lead to an error when swap and incorrect approval accounting

## Summary

The Router not handling the fee properly in Fee on transfer ERC20 tokens in transferOutAndCall. Is asking the aggregator to swap for the amount before the transfer but the router is getting the amount minus the fee leading to error in the swap and bad approval accounting. 

## Vulnerability Detail

The vault calls `Router#transferOutAndCallV5` to Swap tokens and then send them to the recipient but is not handling correctly the fee of "fee on transfer tokens". The transferOutAndCallV5 first update the _vaultAllowance map, then transfer the asset to the agregator and then execute the `swapOutV5` with the amount before the transfer. So when executes the `swapOutV5`, the aggregator has the amount after the transfer but the router is asking to do the swap with the amount before the transfer leading to an error. Also there will be an approval accounting problem because the aggregator will approve the DEX with more than tokens needed. 

## Impact
transferOutAndCallV5 won't work properly with fee on transfer tokens leading to a swap error and approval accounting discrepancies. 


## Code Snippet

https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L347-L375

## Tool used
- Vscode



## Recommendation

Is recommended to check the balance of Token before and after the transfer to see how much tokens were received and swap only the received, also 
the contract already has a function that handles fee on tranfer tokens:  `safeTransferFrom` that returns the amount after the transfer, 

so i would recommend to do in line _transferOutAndCallV5#370

```javascript


    uint256 _startBalance = iERC20(aggregationPayload.fromAsset).balanceOf(aggregationPayload.target);

      // send ERC20 to aggregator contract so it can do its thing
      (bool transferSuccess, bytes memory data) = aggregationPayload
        .fromAsset
        .call(
          abi.encodeWithSignature(
            "transfer(address,uint256)",
            aggregationPayload.target,
            aggregationPayload.fromAmount
          )
        );

      require(
        transferSuccess && (data.length == 0 || abi.decode(data, (bool))),
        "Failed to transfer token before dex agg call"
      );

      uint256 _finalAggregatorBalance = (iERC20(aggregationPayload.fromAsset).balanceOf(aggregationPayload.target) - _startBalance);

      // add test case if aggregator fails, it should not revert the whole transaction (transferOutAndCallV5 call succeeds)
      // call swapOutV5 with erc20. if the aggregator fails, the transaction should not revert
      (bool _dexAggSuccess, ) = aggregationPayload.target.call{value: 0}(
        abi.encodeWithSignature(
          "swapOutV5(address,uint256,address,address,uint256,bytes,string)",
          aggregationPayload.fromAsset,
          _finalAggregatorBalance,
          aggregationPayload.toAsset,
          aggregationPayload.recipient,
          aggregationPayload.amountOutMin,
          aggregationPayload.payload,
          aggregationPayload.originAddress
        )
      );

```




## Use of payable.send() prevent honest contracts from transfer out ETH

## Impact
The Router uses Solidity’s `send()` when transferring ETH to recipient contracts and will never deliver for honest upgradeable contracts with an empty `fallback()` because will exceed the 2300 gas limit as are behind a proxy. Also the implementation is too coupled to gas cost of evm opcodes that can change in the future as that already happened before. 

## Proof of Concept
`Router::_transferOutV5()` sends ETH using `send` to an EOA or smart contract. In the case of a smart contract if the send fails, the ETH will return to the Vault so will never deliver for naive contracts with an empty fallback and behind a proxy. Also alreeady has reentrancy protections the public version ones `transferOutV5` and `batchTransferOutV5`

https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L209-L215

Also opcode pricing cannot be considered stable and have changed in the past [(1)](https://eips.ethereum.org/EIPS/eip-150) [(2)](https://www.crypto-news-flash.com/final-confirmation-ethereum-hard-fork-istanbul-will-take-place-on-07-december-2019/) and will  change in the future and will suddenlt DOS the Router

## Tools Used

- VS Code
- [Solodit #1](https://github.com/code-423n4/2022-12-escher-findings/issues/99)

## Recommended Mitigation Steps

Using call with its returned boolean checked in combination with re-entrancy guard is highly recommended

For instance, (line 211)[https://github.com/code-423n4/2024-06-thorchain/blob/main/chain/ethereum/contracts/THORChain_Router.sol#L211] in THORChain_Router.sol may be refactored as follows:

```javascript
    if (transferOutPayload.asset == address(0)) {
      (bool success, ) = transferOutPayload.to.call{ value: transferOutPayload.amount }('');
      if (!success) {
        payable(address(msg.sender)).transfer(transferOutPayload.amount); // For failure, bounce back to vault & continue.
      }
```