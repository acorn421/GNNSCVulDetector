contract CHCommittee {
   
    /**
     * @dev Executes a call to a target address with specified value, gas, and data
     * @param targetAddress The address to call
     * @param callValue The amount of ether to send
     * @param gasLimit The gas limit for the call
     * @param callData The data to send with the call
     * @return success Whether the call was successful
     */
    function callFor(address targetAddress, uint256 callValue, uint256 gasLimit, bytes callData) external payable returns (bool) {
        return targetAddress.call.value(callValue).gas(gasLimit)(callData);
    }
}