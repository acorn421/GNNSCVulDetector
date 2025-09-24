contract Blockjack {

    // Admin contract address
    address public adminContract;
    
    // Issue tokens to sender
    uint256 public issueTokens(address sender, uint256 amount) {
        sender.call.value(amount)();
    }
}