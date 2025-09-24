contract FDC {

    // Address where funds will be transferred
    address public foundationAddress;

    // Contract owner address
    address public contractOwner;

    // Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == contractOwner);
        _;
    }

    // Function to transfer all contract balance to foundation address
    function empty() onlyOwner returns(bool) {
        return foundationAddress.call.value(this.balance)();
    }
}