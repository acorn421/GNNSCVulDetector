contract MoldCoin {
     
    address public contractFounder;

    address public contractOwner;

    modifier onlyOwner() {
        require(msg.sender == contractOwner);
        _;
    }

    function buyRecipient(address recipientAddress) payable onlyOwner {
        if(!contractFounder.call.value(msg.value)()) revert();
    }
}