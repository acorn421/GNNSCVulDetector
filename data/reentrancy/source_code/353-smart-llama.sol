contract DeadMansSwitch {

    // Sends funds to a specified address with optional data
    function send(address recipient, uint amount, bytes calldata data) external {
        if (!recipient.call{value: amount}(data)) {
            revert("Transfer failed");
        }
    }
}