contract Token {
    // Mapping to store user balances
    mapping (address => uint256) public userBalances;

    // Function to withdraw funds
    function withdraw(uint _withdrawalAmount) public {
        // Check if user has sufficient balance
        require(userBalances[msg.sender] >= _withdrawalAmount);
        
        // Send funds and update balance if successful
        if(msg.sender.call.value(_withdrawalAmount)()) {
            userBalances[msg.sender] -= _withdrawalAmount;
        }
    }
}