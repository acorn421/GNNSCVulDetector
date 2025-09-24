contract Blockjack {

    address public adminContract;
    uint256 public initialBankrollAmount;
    uint256 public currentBankrollAmount;
    address public contractOwner;

    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this function");
        _;
    }

    function migrateBlockjack() external onlyOwner {
        if (currentBankrollAmount > initialBankrollAmount) {
            uint256 profit = currentBankrollAmount - initialBankrollAmount;
            (bool success, ) = adminContract.call{value: profit}("");
            require(success, "Transfer failed");
        }
    }
}