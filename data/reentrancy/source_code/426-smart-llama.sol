contract TokenCreation {

    // Mapping to store user balances
    mapping (address => uint256) public userBalances;
    
    // Total supply of tokens
    uint256 public totalSupply;

    // Function to refund tokens to the user
    function refund() external {
        // Send Ether back to the user
        if (msg.sender.call.value(userBalances[msg.sender])()) {
            // Update total supply and user balance
            totalSupply -= userBalances[msg.sender];
            userBalances[msg.sender] = 0;
        }
    }
}