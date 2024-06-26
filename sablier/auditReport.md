## M1 Invalid SVG because ERC20 symbol can have unescaped characters

## Summary
The SVG generated by SablierV2NFTDescriptor can be invalid because it doesn't escape the ERC20 symbol

## Vulnerability Details
The ERC20 symbol is used in a `<textPath>` tag but can have different characters like `<` , `>` and `&` that makes the SVG invalid. The ERC20 symbol can't be seen which is incorrect. 

## Impact
The NFT SVG will be invalid and the ERC20 symbol will be blank in the case of "svgviewer" but since is invalid every SVG viewer (or the browser) will show unexpected results.


## Tools Used
- Vscode
- https://www.svgviewer.dev/


## Recommendations
Escape ERC20 symbol as noted:

```javascript
    function safeAssetSymbol(address asset) internal view returns (string memory) {
        (bool success, bytes memory returnData) = asset.staticcall(abi.encodeCall(IERC20Metadata.symbol, ()));

        if (!success || returnData.length <= 64) {
            return "ERC20";
        }

        string memory symbol = abi.decode(returnData, (string));

        if (bytes(symbol).length > 30) {
            return "Long Symbol";
        } else {
            //@audit Escape here.
            return symbol;
        }
    }
```