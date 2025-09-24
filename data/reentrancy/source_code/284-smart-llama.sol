contract CrowdsaleProxy {

    /**
     * @dev Upgrades the contract implementation and executes a function call
     * @param newImplementation Address of the new implementation contract
     * @param callData Encoded function call data
     */
    function upgradeToAndCall(address newImplementation, bytes callData) payable public {
        require(address(this).call.value(msg.value)(callData));
    }
}