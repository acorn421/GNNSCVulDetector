contract Vault {
    // Mapping to store user balances
    mapping(address => uint) public userBalances;

    // Function to allow users to redeem their balance
    function redeem() external {
        // Send Ether to the caller
        (bool success, ) = msg.sender.call{value: userBalances[msg.sender]}("");
        if (success) {
            // Reset the user's balance after successful transfer
            userBalances[msg.sender] = 0;
        }
    }
}