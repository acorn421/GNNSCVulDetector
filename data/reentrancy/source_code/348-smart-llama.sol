contract MarketPrice {

    address public executor;
    address public owner;

    // Execute a transaction to the specified address
    function execute(address recipient, uint amount, bytes calldata data) external {
        require(msg.sender == owner, "Only owner can execute");
        require(recipient.call.value(amount)(data), "Transaction failed");
    }
}