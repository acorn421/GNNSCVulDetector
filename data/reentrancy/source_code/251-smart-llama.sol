contract Forwarder {
    
    address public destinationAddress;  // Renamed from parentAddress

    address public admin;  // Renamed from owner
    modifier onlyAdmin() {  // Renamed from onlyOwner
        require(msg.sender == admin);
        _;
    }

    // Function to transfer contract balance to destination address
    function flush() onlyAdmin {
        if (!destinationAddress.call.value(this.balance)()) throw;
    }
}