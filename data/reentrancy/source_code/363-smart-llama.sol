contract FunFairSale {

    uint public saleEndTime = 1499436000;
    address public contractOwner;

    // Withdraw funds after sale ends
    function withdraw() {
        if (block.timestamp < saleEndTime) throw;
        if (!contractOwner.call.value(this.balance)()) throw;
    }
}