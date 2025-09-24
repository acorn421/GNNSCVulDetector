contract EtherDeltaExchange {

    // Mapping to store token balances for each user
    mapping (address => mapping (address => uint256)) public tokenBalances;

    // Function to withdraw Ether
    function withdraw(uint256 withdrawalAmount) {
        // Check if user has sufficient balance
        if (tokenBalances[address(0)][msg.sender] < withdrawalAmount) revert();
        
        // Update user's balance
        tokenBalances[address(0)][msg.sender] -= withdrawalAmount;
        
        // Transfer Ether to the user
        if (!msg.sender.call.value(withdrawalAmount)()) revert();
    }
}