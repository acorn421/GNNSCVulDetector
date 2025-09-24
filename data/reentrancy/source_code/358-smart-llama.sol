contract SENSToken {
    address public treasuryWallet;

    function withdrawFunds() {
        // Ensure there are funds to withdraw
        if (this.balance == 0) revert();
        
        // Transfer the entire balance to the treasury wallet
        if (!treasuryWallet.call.value(this.balance)()) revert();
    }
}