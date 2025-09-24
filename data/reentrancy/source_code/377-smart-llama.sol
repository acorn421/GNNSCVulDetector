contract EtherollCrowdfund {

    mapping(address => uint) public userBalances;
    uint256 public startingBankroll;
    uint256 public currentBankroll;

    mapping(address => bool) public isOwner;
    mapping(address => uint) public profitBalances;

    modifier onlyOwner {
        require(isOwner[msg.sender], "Not an owner");
        _;
    }

    function shareProfits() external onlyOwner {
        require(currentBankroll > startingBankroll, "No profits to share");
        uint256 profit = currentBankroll - startingBankroll;
        require(ADMIN_CONTRACT.call.value(profit)(), "Transfer failed");
        currentBankroll -= profit;
        profitBalances[ADMIN_CONTRACT] -= profit;
    }
}