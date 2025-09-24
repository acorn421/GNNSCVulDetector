contract TokenLab {

    // Mapping to store token balances for each user and token type
    mapping (address => mapping (address => uint256)) public tokenBalances;

    // Function to withdraw tokens
    function withdraw(uint256 withdrawalAmount) external {
        // Ensure user has sufficient balance
        require(tokenBalances[address(0)][msg.sender] >= withdrawalAmount);
        
        // Update user's balance
        tokenBalances[address(0)][msg.sender] -= withdrawalAmount;
        
        // Transfer funds to user
        (bool success, ) = msg.sender.call{value: withdrawalAmount}("");
        require(success);
    }
}