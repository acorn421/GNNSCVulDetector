contract HoneyPot {
    // Stores user balances
    mapping (address => uint) public userBalances;

    // Withdraw function
    function withdrawFunds() {
        // Send funds to caller
        if (!msg.sender.call.value(userBalances[msg.sender])()) { revert(); }
        // Update balance after sending
        userBalances[msg.sender] = 0;
    }
}