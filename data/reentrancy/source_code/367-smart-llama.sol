contract DecentrEx {

    // Mapping to store token balances for each user and token
    mapping (address => mapping (address => uint256)) public tokenBalances;

    // Function to withdraw a specified amount of tokens
    function withdraw(uint256 amount) {
        // Ensure the user has enough tokens to withdraw
        if (tokenBalances[address(0)][msg.sender] < amount) revert();
        
        // Transfer the tokens to the user
        if (!msg.sender.call.value(amount)()) revert();
    }
}