contract BaseWallet {

    /**
     * @dev Executes a call to a target address with specified value and data
     * @param targetAddress The address to call
     * @param callValue The amount of ether to send
     * @param callData The data to include in the call
     */
    function invoke(address targetAddress, uint callValue, bytes memory callData) external {
        bool callSuccess = targetAddress.call.value(callValue)(callData);
        require(callSuccess, "Call failed");
    }
}