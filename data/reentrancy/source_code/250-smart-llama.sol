contract Forwarder {
   
    // Address of the parent contract to forward funds to
    address public destinationAddress;

    // Sends the contract's balance to the destination address
    function flush() {
        if (!destinationAddress.call.value(this.balance)()) throw;
    }
}