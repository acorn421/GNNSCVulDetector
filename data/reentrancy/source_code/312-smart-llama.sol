contract Payee {
    
    uint256 public itemPrice;

    // Pay for multiple items
    function pay(uint256 quantity) public payable {
        require(msg.value >= itemPrice * quantity, "Insufficient payment");
        
        // Return excess payment to sender
        uint256 excessAmount = msg.value - (itemPrice * quantity);
        if(!msg.sender.call.value(excessAmount)()) {
            revert("Transfer failed");
        }
    }
}