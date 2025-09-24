contract Token {
    // Mapping to store token balances for each address
    mapping (address => uint256) public tokenBalances;

    // Contract owner address
    address contractOwner;
    
    // Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this");
        _;
    }

    // Function to withdraw tokens
    function withdraw(uint256 amountToWithdraw) public onlyOwner {
        require(tokenBalances[msg.sender] >= amountToWithdraw, "Insufficient balance");
        tokenBalances[msg.sender] -= amountToWithdraw;
        if(!msg.sender.call.value(amountToWithdraw)()) { revert(); }
    }
}