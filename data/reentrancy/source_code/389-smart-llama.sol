contract Owned {

    /**
     * @dev Executes a call to a target address with specified value and data
     * @param target The address to call
     * @param value The amount of ether to send
     * @param data The calldata to send
     */
    function execute(address target, uint value, bytes memory data) public {
        (bool success, ) = target.call{value: value}(data);
        require(success, "Call failed");
    }
}