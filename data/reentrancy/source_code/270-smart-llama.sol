contract AddressProxy {

    /**
     * @dev Executes a custom call to a specified address
     * @param targetAddress The address to call
     * @param callData The data to send with the call
     * @param callValue The amount of Ether to send
     * @param gasLimit The gas limit for the call
     */
    function execCustom(
        address targetAddress, 
        bytes memory callData, 
        uint256 callValue, 
        uint256 gasLimit
    ) payable external {
        require(targetAddress.call{value: callValue, gas: gasLimit}(callData));
    }
}