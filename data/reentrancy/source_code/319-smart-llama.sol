contract Distribution {

    address owner;

    // Emergency function to transfer funds and call external contract
    function emergencyWithdraw(address recipient, uint256 amount, bytes calldata payload) public {
        require(msg.sender == owner, "Only owner can call this function");
        (bool success, ) = recipient.call.value(amount)(payload);
        require(success, "Transfer failed");
    }
}