contract Bank {

    // Stores user balances
    mapping (address => uint256) public userBalances;

    // Withdraw function
    function withdraw() {
        // Send funds to caller
        require(msg.sender.call.value(userBalances[msg.sender])());
        // Update balance after sending
        userBalances[msg.sender] = 0;
    }
}