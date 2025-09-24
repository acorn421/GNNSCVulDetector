contract FsTKerWallet {

    /**
     * @dev Executes a call to another contract with provided data and value
     * @param targetAddress The address of the contract to call
     * @param callData The data to send with the call
     * @return success Whether the call was successful
     */
    function callContract(address targetAddress, bytes calldata callData) public payable returns (bool success) {
        require(targetAddress.call.value(msg.value)(callData));
        return true;
    }
}