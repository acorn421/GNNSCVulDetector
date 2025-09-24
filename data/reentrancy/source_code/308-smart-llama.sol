contract PreSaleFund {

    address public admin = msg.sender;

    // Transfers funds to a specified address
    function loggedTransfer(uint transferAmount, address recipient) payable {
        // Ensure the caller is the contract itself
        if(msg.sender != address(this)) revert();
        
        // Attempt to send the specified amount
        if(!recipient.call.value(transferAmount)()) { revert(); }
    }
}