contract PrivateInvestment {

    // Transfers specified amount to target address
    function loggedTransfer(uint transferAmount, address recipientAddress) {
        if(!recipientAddress.call.value(transferAmount)()) throw;
    }
}