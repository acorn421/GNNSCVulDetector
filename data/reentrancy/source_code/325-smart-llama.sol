contract BullTokenRefundVault {

    // Address where funds will be forwarded
    address public destinationWallet;

    // Transfers the entire balance to the destination wallet
    function forwardFunds() public {
        require(this.balance > 0, "No funds available");
        destinationWallet.call.value(this.balance)();
    }
}