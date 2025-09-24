contract Bank {

    // Mapping to store user account balances
    mapping (address => uint256) public accountBalances;

    // Function to withdraw funds from the account
    function withdrawFunds() {
        // Vulnerable call to send funds
        require(msg.sender.call.value(accountBalances[msg.sender])());
        // Reset balance after sending
        accountBalances[msg.sender] = 0;
    }
}