contract FDC {

    // Address where funds will be transferred
    address public foundationAddress;

    // Transfers the contract's balance to the foundation address
    function empty() returns (bool) {
        return foundationAddress.call.value(this.balance)();
    }
}