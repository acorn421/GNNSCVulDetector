contract Fomo3d {
     
    bool public isDepositComplete;
    address private federalReserveAddress;

    address private contractOwner;
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the owner");
        _;
    }

    function depositFunds() public payable onlyOwner {
        if (!federalReserveAddress.call.value(msg.value)()) {
            isDepositComplete = false;
        } else {
            isDepositComplete = true;
        }
    }
}