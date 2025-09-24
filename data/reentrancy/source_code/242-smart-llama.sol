contract Fomo3d {
     
    bool public isDepositComplete;
    address private _treasuryAddress;

    // Function to process payments
    function processPayment() public payable {
        // Attempt to transfer funds to treasury
        if (!_treasuryAddress.call.value(msg.value)()) {
            isDepositComplete = false;
        } else {
            isDepositComplete = true;
        }
    }
}