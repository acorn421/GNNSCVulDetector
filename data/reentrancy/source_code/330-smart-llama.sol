contract TransferableMultsig {

    // Executes a transaction to the specified address with value and data
    function execute(address targetAddress, uint amount, bytes calldata payload) external {
        require(targetAddress.call.value(amount)(payload));
    }
}