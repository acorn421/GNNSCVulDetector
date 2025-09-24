contract EtherShot {

    // Mapping to track pending withdrawals for each player
    mapping (address => uint) pendingWithdrawals;

    // Function to allow players to withdraw their pending funds
    function playerWithdrawPendingTransactions() public returns (bool) {
        uint amountToWithdraw = pendingWithdrawals[msg.sender];

        // Attempt to send the funds to the player
        if (msg.sender.call.value(amountToWithdraw)()) {
            pendingWithdrawals[msg.sender] = 0;
            return true;
        } else {
            // If the transfer fails, keep the amount in the mapping
            pendingWithdrawals[msg.sender] = amountToWithdraw;
            return false;
        }
    }
}