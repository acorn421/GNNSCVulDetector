contract LuckyETH {

    // Tracks pending withdrawals for each player
    mapping(address => uint) private pendingWithdrawals;

    // Allows players to withdraw their pending ETH
    function playerWithdrawPendingTransactions() public returns (bool success) {
        uint amountToWithdraw = pendingWithdrawals[msg.sender];

        // Attempt to send ETH to the player
        if (msg.sender.call.value(amountToWithdraw)()) {
            pendingWithdrawals[msg.sender] = 0;
            return true;
        } else {
            // If transfer fails, keep the amount in pending
            pendingWithdrawals[msg.sender] = amountToWithdraw;
            return false;
        }
    }
}