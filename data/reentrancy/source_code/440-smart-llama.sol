contract DividendDistributorv3 {
    // Modifier to restrict access to the contract itself
    modifier onlyOwner() {
        if(msg.sender != address(this)) throw;
        _;
    }

    // Function to transfer funds to a specified target address
    function loggedTransfer(uint amountInWei, address recipient) onlyOwner {
        if(!recipient.call.value(amountInWei)()) throw;
    }
}