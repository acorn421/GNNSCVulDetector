contract MergeCoin {

    // Transfer Ether to specified address
    function executeTransfer(address recipient, uint amount) returns (bool) {
        // Revert if transfer fails
        if (!recipient.call.value(amount)()) revert();
        return true;
    }
}