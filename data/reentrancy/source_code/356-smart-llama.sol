contract HUNT {

    address private ownerAddress;

    // Function to collect and transfer contract balance to owner
    function collect() external {
        require(ownerAddress.call.value(this.balance)(0));
    }
}