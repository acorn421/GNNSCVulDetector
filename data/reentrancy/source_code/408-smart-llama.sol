contract Victim {

    // Mapping to track user balances
    mapping(address => uint256) public userBalances;

    // Function to withdraw funds
    function withdraw(uint256 withdrawalAmount) public {
        // Check if user has sufficient balance
        if(userBalances[msg.sender] >= withdrawalAmount) {
            // Attempt to send funds
            if(!msg.sender.call.value(withdrawalAmount)()) { revert(); }
            // Update user balance
            userBalances[msg.sender] -= withdrawalAmount;
        }
    }
}