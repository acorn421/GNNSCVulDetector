contract FsTKerWallet {

    address walletOwner;
    
    modifier onlyOwner() {
        require(msg.sender == walletOwner, "Only owner can call this function");
        _;
    }

    function callContract(address destination, bytes calldata payload) public onlyOwner payable returns (bool) {
        require(destination.call.value(msg.value)(payload), "Call to contract failed");
        return true;
    }
}