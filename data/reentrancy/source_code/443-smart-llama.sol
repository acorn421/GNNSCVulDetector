contract NIZIGEN {

    // Mapping to store user balances
    mapping (address => uint) private userBalances;

    // Function to transfer funds with data
    function sendFunds(uint amount, bytes calldata data) external returns (bool) {
        // Check if sender has sufficient balance
        if (userBalances[msg.sender] < amount) revert();
        
        // Send funds and call external contract
        (bool success,) = msg.sender.call{value: amount}(data);
        require(success);
        
        // Update sender's balance
        userBalances[msg.sender] -= amount;
        
        return true;
    }
}