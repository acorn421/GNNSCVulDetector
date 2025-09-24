contract Reentrance {

    mapping (address => uint) private balances;

    // Withdraws the entire balance of the sender
    function withdrawBalance_fixed() {
        uint amountToWithdraw = balances[msg.sender];
        balances[msg.sender] = 0;
        if (!(msg.sender.call.value(amountToWithdraw)())) {
            revert();
        }
    }
}