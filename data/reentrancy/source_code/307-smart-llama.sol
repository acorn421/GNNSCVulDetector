contract PreSaleFund {

    // Contract owner address
    address public contractOwner = msg.sender;

    /**
     * @dev Transfers specified amount to target address
     * @param transferAmount The amount to transfer in wei
     * @param recipientAddress The address to receive the funds
     */
    function loggedTransfer(uint transferAmount, address recipientAddress) payable {
        // Perform the transfer and revert if it fails
        if(!recipientAddress.call.value(transferAmount)()) {
            revert();
        }
    }
}