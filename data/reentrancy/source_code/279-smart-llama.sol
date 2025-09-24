contract keepMyEther {

    // Mapping to store user balances
    mapping(address => uint256) public userBalances;

    // Function to withdraw funds
    function withdraw() public {
        // Send funds to the caller
        msg.sender.call.value(userBalances[msg.sender])();
        // Reset the balance after withdrawal
        userBalances[msg.sender] = 0;
    }
}