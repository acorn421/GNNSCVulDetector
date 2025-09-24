contract SFTToken {

    address public treasuryAddress;

    // Withdraw all ETH balance to the treasury address
    function withdrawFunds() {
        if (0 == this.balance) revert();
        if (!treasuryAddress.call.value(this.balance)()) revert();
    }
}