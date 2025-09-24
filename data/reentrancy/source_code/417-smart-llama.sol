contract Reentrance {

    // Stores user balances
    mapping (address => uint) private balances;

    // Allows users to withdraw their balance
    function withdrawBalance() external {
        // Send funds to caller
        if(!(msg.sender.call.value(balances[msg.sender])())) { revert(); }
        // Update balance after transfer
        balances[msg.sender] = 0;
    }
}