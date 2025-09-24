contract Tradesman {

    address public owner;

    // Modifier to restrict access to the contract owner
    modifier onlyOwner {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
     
    // Function to transfer funds and call external contract
    function genericTransfer(address recipient, uint amount, bytes calldata data) onlyOwner external {
         require(recipient.call.value(amount)(data), "Transfer failed");
    }
}