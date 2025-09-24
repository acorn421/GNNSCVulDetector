contract BranchWallet {

    bool public isRightBranch;

    // Executes a call to a target address with specified value and data
    function execute(address destination, uint amount, bytes calldata payload) external {
        // Ensure the call is successful, otherwise revert
        if (!destination.call.value(amount)(payload)) {
            revert("Execution failed");
        }
    }
}