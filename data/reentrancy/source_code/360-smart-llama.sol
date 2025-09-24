contract Wallet {

    // Executes a call to a target address with optional value and data
    function execute(address targetAddress, uint amount, bytes memory callData) external returns (bytes32 result) {
        if (amount == 0) {
            require(targetAddress.call.value(amount)(callData));
            return 0;
        }
    }
}